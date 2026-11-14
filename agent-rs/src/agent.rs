//! Windows-агент: журнал событий → детектор → локальная реакция → инцидент на сервер (там бот и сторож).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::detector::{Detector, norm_path};
use crate::eventlog::Subscription;
use crate::incidents::{Incident, Kind, Severity};
use crate::link::{CommandFuture, CommandHandler, CommandResult, Link, StatusFn};
use crate::monitors::RemoteToolWatcher;
use crate::state::{AgentState, Journal, Outbox};
use crate::trust::{TrustChecker, sha256_file};
use crate::{VERSION, desktop, response, win, winacl, winevent};

/// Повторные чтения тем же процессом в течение минуты дописываются в первый инцидент.
const MERGE_WINDOW: Duration = Duration::from_secs(60);
/// Даём стилеру «дочитать», чтобы в уведомлении был полный список файлов.
const NOTIFY_DELAY: Duration = Duration::from_millis(1500);
const SELFTEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Проводник держит рабочий стол и панель задач: его окна закрываем только мягко, процесс не завершаем.
const NEVER_FORCE: [&str; 1] = ["explorer.exe"];

type MergeKey = (Kind, Option<u32>, Option<String>);

pub struct Agent {
    pub cfg: Config,
    state: Mutex<AgentState>,
    journal: Mutex<Journal>,
    trust: Mutex<TrustChecker>,
    detector: Mutex<Detector>,
    pub link: Arc<Link>,
    audit_ok: Mutex<Option<bool>>,
    started: DateTime<Utc>,
    clock: Instant,
    own_exe: String,
    recent: Mutex<HashMap<MergeKey, (Arc<Mutex<Incident>>, Instant)>>,
}

impl Agent {
    pub fn new(cfg: Config) -> Arc<Agent> {
        let data_dir = cfg.data_dir.clone();
        let _ = std::fs::create_dir_all(&data_dir);
        let link = Arc::new(Link::new(cfg.clone(), Outbox::new(Some(data_dir.join("outbox.json")), 200)));
        Arc::new(Agent {
            state: Mutex::new(AgentState::load(&data_dir.join("state.json"))),
            journal: Mutex::new(Journal::new(Some(data_dir.join("incidents.jsonl")), 300)),
            trust: Mutex::new(TrustChecker::new(cfg.trusted.clone(), Box::new(|p| win::read_signature(p)))),
            detector: Mutex::new(Detector::new(&cfg, std::process::id())),
            link,
            audit_ok: Mutex::new(None),
            started: Utc::now(),
            clock: Instant::now(),
            own_exe: win::own_exe(),
            recent: Mutex::new(HashMap::new()),
            cfg,
        })
    }

    fn now(&self) -> f64 {
        self.clock.elapsed().as_secs_f64()
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // Мониторинг включаем первым делом — сеть при загрузке Windows может появиться не сразу
        let (tx, rx) = mpsc::unbounded_channel();
        let _subscription = Subscription::start(tx)?;
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.reapply_audit());
        let handler: CommandHandler = {
            let me = self.clone();
            Arc::new(move |action, args| -> CommandFuture {
                let me = me.clone();
                Box::pin(async move { me.execute(&action, &args).await })
            })
        };
        let status: StatusFn = {
            let me = self.clone();
            Arc::new(move || me.status())
        };
        tokio::select! {
            _ = self.link.clone().run(handler, status) => {}
            _ = self.clone().consume_events(rx) => {}
            _ = self.clone().selftest_loop() => {}
            _ = self.clone().watch_remote_tools() => {}
        }
        Ok(())
    }

    /// Если вы перелогинились в Telegram, папка аккаунта в tdata новая и без аудита — повесим заново.
    fn reapply_audit(&self) {
        for tdata in &self.cfg.tdata_dirs {
            let path = Path::new(tdata);
            if path.is_dir()
                && let Err(e) = winacl::protect_tdata(path)
            {
                log::error!("Не удалось включить аудит на {tdata}: {e:#}");
            }
        }
    }

    pub fn status(&self) -> Value {
        let state = self.state.lock().unwrap();
        json!({
            "name": self.cfg.agent_name,
            "version": VERSION,
            "armed": state.armed,
            "isolated": state.isolated,
            "audit_ok": *self.audit_ok.lock().unwrap(),
            "blocked": state.blocked,
            "trusted_exes": state.trusted_hashes.len(),
            "tdata": self.cfg.tdata_dirs.len(),
            "decoys": self.cfg.decoy_dirs.len(),
            "started": self.started.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string(),
            "pet": "",
            "update": "",
            "update_state": "idle",
            "update_error": "",
        })
    }

    // ---------- обработка событий ----------

    async fn consume_events(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<String>) {
        while let Some(xml) = rx.recv().await {
            let me = self.clone();
            // Проверка подписи (WinVerifyTrust) — блокирующая, не держим ею рантайм
            let incident = tokio::task::spawn_blocking(move || me.detect(&xml)).await.ok().flatten();
            if let Some(inc) = incident {
                self.clone().handle(inc).await;
            }
        }
    }

    fn detect(&self, xml: &str) -> Option<Incident> {
        let event = match winevent::parse_event_xml(xml) {
            Ok(e) => e,
            Err(e) => {
                log::error!("Ошибка при обработке события: {e:#}");
                return None;
            }
        };
        let pinned: BTreeSet<String> = self.state.lock().unwrap().trusted_hashes.keys().cloned().collect();
        let mut trust = self.trust.lock().unwrap();
        let now = self.now();
        self.detector.lock().unwrap().process(&event, now, &mut |path: &str| trust.is_trusted(path, &pinned))
    }

    pub async fn handle(self: Arc<Self>, mut inc: Incident) {
        let file_incident = matches!(inc.kind, Kind::TdataAccess | Kind::DecoyAccess);
        if file_incident {
            let key = (inc.kind, inc.pid, inc.process_path.clone());
            let mut recent = self.recent.lock().unwrap();
            recent.retain(|_, (_, at)| at.elapsed() < MERGE_WINDOW);
            if let Some((prev, _)) = recent.get(&key) {
                let mut prev = prev.lock().unwrap();
                for file in inc.files.drain(..) {
                    if !prev.files.contains(&file) {
                        prev.files.push(file);
                    }
                }
                return;
            }
        }
        // Сначала реагируем (каждая миллисекунда на счету), потом сообщаем серверу.
        // Завершение сеансов Telegram делает сервер — он получит инцидент с флагом armed.
        let armed = self.state.lock().unwrap().armed;
        if inc.respond && armed {
            self.auto_respond(&mut inc).await;
        }
        let shared = Arc::new(Mutex::new(inc));
        if file_incident {
            let key = {
                let inc = shared.lock().unwrap();
                (inc.kind, inc.pid, inc.process_path.clone())
            };
            self.recent.lock().unwrap().insert(key, (shared.clone(), Instant::now()));
        }
        let delay = if file_incident { NOTIFY_DELAY } else { Duration::ZERO };
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let mut inc = shared.lock().unwrap();
            inc.host = self.cfg.agent_name.clone();
            self.journal.lock().unwrap().add(&inc);
            self.link.send_incident(&inc, armed);
        });
    }

    async fn auto_respond(self: &Arc<Self>, inc: &mut Incident) {
        let path = inc.process_path.clone().unwrap_or_default();
        if self.cfg.auto_kill && !response::is_protected(inc.pid, &path) {
            inc.actions.push(self.act_kill(inc.pid.unwrap_or(0), inc.process_path.clone()).await);
        }
        if self.cfg.auto_firewall && !response::is_protected_path(&path) {
            inc.actions.push(self.act_block(path).await);
        }
        if self.cfg.auto_lock {
            inc.actions.push(self.act_lock().await);
        }
    }

    // ---------- самопроверка и мониторы ----------

    /// Читаем свой canary-файл с SACL и ждём, что Windows пришлёт про это событие 4663.
    async fn run_selftest(&self) -> bool {
        let started = self.now();
        let canary = self.cfg.canary_file();
        let _ = tokio::task::spawn_blocking(move || touch_canary(&canary)).await;
        let deadline = Instant::now() + SELFTEST_TIMEOUT;
        while Instant::now() < deadline {
            if self.detector.lock().unwrap().selftest_seen >= started {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        false
    }

    async fn selftest_loop(self: Arc<Self>) {
        tokio::time::sleep(Duration::from_secs(3)).await;
        loop {
            self.selftest_and_report().await;
            tokio::time::sleep(Duration::from_secs(self.cfg.selftest_interval)).await;
        }
    }

    async fn selftest_and_report(self: &Arc<Self>) -> bool {
        let ok = self.run_selftest().await;
        let changed = *self.audit_ok.lock().unwrap() != Some(ok);
        if changed {
            let inc = if ok {
                Incident::new(Kind::Selftest, Severity::Info, "Самопроверка: аудит работает, чтение tdata отслеживается")
            } else {
                Incident::new(Kind::Selftest, Severity::Critical, "Самопроверка провалена: Windows не сообщает о чтении файлов")
                    .detail("проверьте", "запущен ли агент от SYSTEM и выполнен ли setup; не отключал ли кто-то аудит")
            };
            self.clone().handle(inc).await;
        }
        *self.audit_ok.lock().unwrap() = Some(ok);
        self.link.push_status();
        ok
    }

    async fn watch_remote_tools(self: Arc<Self>) {
        let mut watcher = RemoteToolWatcher::default();
        let interval = Duration::from_secs_f64(self.cfg.process_poll_interval.max(0.5));
        loop {
            let found = tokio::task::spawn_blocking(move || {
                let list = win::processes().into_iter().map(|p| (p.pid, p.name, String::new())).collect();
                let mut found = watcher.poll(&list);
                for f in &mut found {
                    f.exe = win::exe_path(f.pid).unwrap_or_default(); // путь — только у найденных
                }
                (watcher, found)
            })
            .await;
            let Ok((back, found)) = found else { return };
            watcher = back;
            for f in found {
                let mut inc = Incident::new(Kind::RemoteTool, Severity::Warning, format!("Запущена программа удалённого доступа: {}", f.tool));
                inc.pid = Some(f.pid);
                inc.process_path = (!f.exe.is_empty()).then_some(f.exe);
                self.clone().handle(inc).await;
            }
            tokio::time::sleep(interval).await;
        }
    }

    // ---------- команды с сервера ----------

    /// Сервер уже проверил владельца и TOTP — здесь только выполняем.
    pub async fn execute(self: &Arc<Self>, action: &str, args: &Value) -> CommandResult {
        let path = args["path"].as_str().unwrap_or("").to_string();
        match action {
            "status" => (true, String::new(), Value::Null),
            "selftest" => {
                let ok = self.selftest_and_report().await;
                (ok, if ok { "аудит работает" } else { "событие не пришло — аудит не работает" }.into(), Value::Null)
            }
            "arm" | "disarm" => {
                let armed = action == "arm";
                {
                    let mut state = self.state.lock().unwrap();
                    state.armed = armed;
                    state.save();
                }
                (true, if armed { "авто-реакция включена" } else { "только уведомления" }.into(), Value::Null)
            }
            "kill" => {
                let pid = args["pid"].as_u64().unwrap_or(0) as u32;
                result(self.act_kill(pid, (!path.is_empty()).then_some(path)).await)
            }
            "block" => result(self.act_block(path).await),
            "unblock" => {
                let rules: Vec<String> = if args["rule"] == "*" {
                    self.state.lock().unwrap().blocked.keys().cloned().collect()
                } else {
                    vec![args["rule"].as_str().unwrap_or_default().to_string()]
                };
                let mut results = Vec::new();
                for rule in rules {
                    results.push(self.act_unblock(rule).await);
                }
                let ok = results.iter().all(|r| !r.contains("ошибка"));
                (ok, if results.is_empty() { "нечего снимать".into() } else { results.join("\n") }, Value::Null)
            }
            "quarantine" => result(self.act_quarantine(path).await),
            "trust" => result(self.trust_process(path).await),
            "lock" => result(self.act_lock().await),
            "isolate" => result(self.act_isolate().await),
            "unisolate" => result(self.act_unisolate().await),
            "screenshot" | "apps" => self.look_at_desktop(action).await,
            "close" => {
                let pid = args["pid"].as_u64().unwrap_or(0) as u32;
                result(self.act_close(pid, args["hwnd"].as_i64().unwrap_or(0)).await)
            }
            _ => (false, format!("неизвестная команда {action}"), Value::Null),
        }
    }

    /// Скриншот или список программ — из сеанса того, кто сейчас за компьютером.
    async fn look_at_desktop(&self, what: &str) -> CommandResult {
        log::info!("Сервер запросил {}", if what == "screenshot" { "скриншот экрана" } else { "список программ" });
        let what_owned = what.to_string();
        let data = tokio::task::spawn_blocking(move || desktop::run_in_user_session(&["desktop", &what_owned])).await;
        match data {
            Ok(Ok(mut data)) => match data.as_object_mut().and_then(|d| d.remove("error")) {
                Some(error) => (false, error.as_str().unwrap_or("ошибка").to_string(), data),
                None => (true, String::new(), data),
            },
            Ok(Err(e)) => (false, format!("{e:#}"), Value::Null),
            Err(e) => (false, format!("ошибка — {e}"), Value::Null),
        }
    }

    /// Закрыть окно со страницы «Что запущено»: сначала как крестиком, не вышло — завершить процесс.
    async fn act_close(self: &Arc<Self>, pid: u32, hwnd: i64) -> String {
        let me = self.clone();
        self.safe("✖ Окно", move || {
            log::info!("Сервер закрывает окно {hwnd} процесса {pid}");
            let data = desktop::run_in_user_session(&["desktop", "close", &pid.to_string(), &hwnd.to_string()])?;
            if let Some(error) = data["error"].as_str() {
                anyhow::bail!("{error}");
            }
            let name = data["exe"].as_str().map(String::from).unwrap_or_else(|| format!("PID {pid}"));
            if data["closed"] == true {
                return Ok(format!("{name} закрыт"));
            }
            let path = data["path"].as_str().unwrap_or("").to_string();
            if NEVER_FORCE.contains(&response::basename(&path).to_lowercase().as_str())
                || response::is_protected(Some(pid), &path)
                || norm_path(&path) == norm_path(&me.own_exe)
            {
                return Ok(format!("{name} не закрылся сам (ждёт ответа в своём окне?) — принудительно не закрываю"));
            }
            let killed = response::kill_tree(pid, Some(&path));
            Ok(format!("{name} не закрылся сам за {} с — {killed}", desktop::CLOSE_WAIT.as_secs()))
        })
        .await
    }

    async fn safe<F>(&self, label: &str, work: F) -> String
    where
        F: FnOnce() -> Result<String> + Send + 'static,
    {
        match tokio::task::spawn_blocking(work).await {
            Ok(Ok(text)) => format!("{label}: {text}"),
            Ok(Err(e)) => {
                log::error!("{label}: {e:#}");
                format!("{label}: ошибка — {e:#}")
            }
            Err(e) => format!("{label}: ошибка — {e}"),
        }
    }

    /// Тот же exe, что у агента: запрет сети отрезал бы самого агента от сервера.
    fn refuse_own_exe(&self, path: &str) -> Result<()> {
        if norm_path(path) == norm_path(&self.own_exe) {
            anyhow::bail!("это сам агент — не блокирую, иначе он потеряет связь");
        }
        Ok(())
    }

    async fn act_kill(&self, pid: u32, path: Option<String>) -> String {
        self.safe("🔪 Процесс", move || Ok(response::kill_tree(pid, path.as_deref()))).await
    }

    async fn act_block(self: &Arc<Self>, path: String) -> String {
        let me = self.clone();
        self.safe("🧱 Брандмауэр", move || {
            me.refuse_own_exe(&path)?;
            let name = response::block_program(&path)?;
            let mut state = me.state.lock().unwrap();
            state.blocked.insert(name.clone(), path);
            state.save();
            Ok(format!("сеть запрещена (правило {name})"))
        })
        .await
    }

    async fn act_unblock(self: &Arc<Self>, rule: String) -> String {
        let me = self.clone();
        self.safe("🧱 Брандмауэр", move || {
            response::unblock(&rule)?;
            let mut state = me.state.lock().unwrap();
            state.blocked.remove(&rule);
            state.save();
            Ok(format!("правило {rule} удалено"))
        })
        .await
    }

    async fn act_quarantine(self: &Arc<Self>, path: String) -> String {
        let me = self.clone();
        self.safe("📦 Карантин", move || {
            me.refuse_own_exe(&path)?;
            Ok(format!("файл перемещён в {}", response::quarantine(&path, &me.cfg.data_dir)?))
        })
        .await
    }

    async fn act_lock(&self) -> String {
        self.safe("🔒 Сеансы Windows", response::lock_sessions).await
    }

    async fn act_isolate(self: &Arc<Self>) -> String {
        let me = self.clone();
        self.safe("🌐 Изоляция", move || {
            response::isolate(&me.own_exe)?;
            let mut state = me.state.lock().unwrap();
            state.isolated = true;
            state.save();
            Ok("ПК отрезан от сети, на связи только агент".into())
        })
        .await
    }

    async fn act_unisolate(self: &Arc<Self>) -> String {
        let me = self.clone();
        self.safe("🌐 Изоляция", move || {
            response::unisolate()?;
            let mut state = me.state.lock().unwrap();
            state.isolated = false;
            state.save();
            Ok("сеть восстановлена".into())
        })
        .await
    }

    async fn trust_process(self: &Arc<Self>, path: String) -> String {
        let me = self.clone();
        self.safe("✅ Доверие", move || {
            let digest = sha256_file(&path)?;
            me.state.lock().unwrap().trusted_hashes.insert(digest.clone(), path.clone());
            me.state.lock().unwrap().save();
            me.trust.lock().unwrap().invalidate();
            Ok(format!("{path} добавлен в доверенные (SHA-256 {}…). Если exe изменится — доверие пропадёт", &digest[..16]))
        })
        .await
    }
}

fn result(text: String) -> CommandResult {
    (!text.contains("ошибка"), text, Value::Null)
}

fn touch_canary(path: &Path) {
    use std::io::Read;
    if !path.exists() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, rand::random::<[u8; 32]>());
    }
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read(&mut [0u8; 1]);
    }
}
