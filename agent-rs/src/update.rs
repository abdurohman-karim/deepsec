//! Обновление агента из GitHub Releases (как deepsec/update.py): найти новую версию, скачать установщик,
//! сверить SHA-256, поставить тихо отдельной задачей планировщика. Настройки, состояние и задача агента
//! остаются как были.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::win;

pub const TASK_NAME: &str = "DeepSec Update";
/// Обновлялись из окна — после перезапуска агент откроет его снова.
pub const REOPEN_FLAG: &str = "reopen-window";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Отдельная задача от SYSTEM: установщик останавливает задачу агента вместе с её процессами, поэтому
/// запускать его из самого агента нельзя — он погиб бы на середине.
const PS_RUN_INSTALLER: &str = r#"
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute $env:DEEPSEC_INSTALLER -Argument $env:DEEPSEC_ARGS
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName $env:DEEPSEC_TASK -Action $action -Principal $principal -Settings $settings `
    -Force | Out-Null
Start-ScheduledTask -TaskName $env:DEEPSEC_TASK
"#;

#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub name: String,
}

pub fn parse_version(value: &str) -> Vec<u64> {
    value.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).take(3).filter_map(|s| s.parse().ok()).collect()
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    parse_version(candidate) > parse_version(current)
}

/// Установщик из ответа GitHub API. Без SHA-256 от GitHub или с чужой ссылкой — не берём.
pub fn release_from_json(data: &Value, repo: &str) -> Option<Release> {
    let prefix = format!("https://github.com/{repo}/releases/download/");
    data["assets"].as_array()?.iter().find_map(|asset| {
        let name = asset["name"].as_str()?;
        let version = name.strip_prefix("DeepSecSetup-")?.strip_suffix(".exe")?;
        let digest = asset["digest"].as_str()?.strip_prefix("sha256:")?;
        let url = asset["browser_download_url"].as_str()?;
        let three = version.split('.').count() == 3 && version.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
        (three && url.starts_with(&prefix)).then(|| Release { version: version.into(), url: url.into(), sha256: digest.to_lowercase(), name: name.into() })
    })
}

fn http() -> ureq::Agent {
    // ureq собран без своего криптопровайдера — даём тот же ring, что у связи с сервером
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    // Тайм-аут на соединение и ответ, а не на весь запрос: 20 МБ на медленном интернете качаются дольше 30 с
    ureq::Agent::config_builder()
        .timeout_connect(Some(TIMEOUT))
        .timeout_recv_response(Some(TIMEOUT))
        .timeout_recv_body(Some(Duration::from_secs(15 * 60)))
        .http_status_as_error(false)
        .tls_config(tls)
        .build()
        .into()
}

pub fn latest_release(repo: &str) -> Result<Option<Release>> {
    let mut response = http()
        .get(&format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "DeepSec-agent")
        .call()
        .map_err(|e| anyhow!("GitHub не ответил: {e}"))?;
    match response.status().as_u16() {
        404 => Ok(None), // релизов ещё нет
        200 => {
            let data: Value = response.body_mut().read_json().map_err(|e| anyhow!("GitHub не ответил: {e}"))?;
            Ok(release_from_json(&data, repo))
        }
        code => bail!("GitHub ответил {code}"),
    }
}

/// Скачать установщик и сверить SHA-256. progress(скачано, всего) — для полосы загрузки в окне.
pub fn download(release: &Release, folder: &Path, progress: &dyn Fn(u64, u64)) -> Result<PathBuf> {
    std::fs::create_dir_all(folder)?;
    let target = folder.join(&release.name);
    let result = (|| -> Result<String> {
        let mut response = http().get(&release.url).header("User-Agent", "DeepSec-agent").call()?;
        if response.status().as_u16() != 200 {
            bail!("сервер ответил {}", response.status());
        }
        let total = response.headers().get("content-length").and_then(|v| v.to_str().ok()?.parse().ok()).unwrap_or(0);
        let mut reader = response.body_mut().as_reader();
        let mut file = std::fs::File::create(&target)?;
        let mut digest = Sha256::new();
        let (mut done, mut buffer) = (0u64, vec![0u8; 256 * 1024]);
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            file.write_all(&buffer[..n])?;
            done += n as u64;
            progress(done, total);
        }
        Ok(hex::encode(digest.finalize()))
    })();
    match result {
        Ok(hash) if hash == release.sha256 => Ok(target),
        Ok(_) => {
            let _ = std::fs::remove_file(&target);
            bail!("SHA-256 скачанного установщика не совпал с опубликованным — файл удалён, ничего не ставлю")
        }
        Err(e) => {
            let _ = std::fs::remove_file(&target);
            bail!("не удалось скачать {}: {e:#}", release.name)
        }
    }
}

pub fn install(installer: &Path, log_dir: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let args = format!(r#"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG="{}""#, log_dir.join("install.log").display());
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PS_RUN_INSTALLER])
        .env("DEEPSEC_INSTALLER", installer)
        .env("DEEPSEC_ARGS", args)
        .env("DEEPSEC_TASK", TASK_NAME)
        .creation_flags(win::CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        bail!("не удалось запустить установщик: {}", win::output_text(&output));
    }
    Ok(())
}

/// Обновлять установщиком можно только установленного агента (exe в Program Files), не собранного из исходников.
pub fn can_update() -> bool {
    win::own_exe().to_lowercase().contains(r"\program files")
}

/// После обновления из окна: с какой версии обновились (окно откроется снова и скажет об этом).
pub fn take_reopen_flag(data_dir: &Path) -> Option<String> {
    let flag = data_dir.join("updates").join(REOPEN_FLAG);
    let previous = std::fs::read_to_string(&flag).ok()?.trim().to_string();
    let _ = std::fs::remove_file(flag);
    Some(previous)
}

/// После обновления: убрать разовую задачу и старые установщики (агент зовёт это через пару минут после старта).
pub fn cleanup(data_dir: &Path) {
    let _ = win::run_hidden("schtasks", &["/Delete", "/TN", TASK_NAME, "/F"]);
    if let Ok(entries) = std::fs::read_dir(data_dir.join("updates")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.starts_with("deepsecsetup-") && name.ends_with(".exe") {
                let _ = std::fs::remove_file(entry.path()); // ещё занят установщиком — удалим в следующий раз
            }
        }
    }
}

const BUSY: [&str; 3] = ["checking", "downloading", "installing"];

#[derive(Default)]
struct UpdaterState {
    /// idle | checking | latest | available | downloading | ready | installing | error
    state: String,
    release: Option<Release>,
    done: u64,
    total: u64,
    error: String,
    installer: Option<PathBuf>,
}

/// Обновление в фоне: проверка → загрузка с прогрессом → установка по команде. Состояние видят окно DeepSec
/// (через локальный канал) и бот (в статусе агента). Окно ставит обновление только после «Перезапустить»,
/// бот — сразу после загрузки.
#[derive(Clone)]
pub struct Updater {
    current: String,
    repo: String,
    folder: PathBuf,
    inner: Arc<Mutex<UpdaterState>>,
    on_change: Arc<dyn Fn() + Send + Sync>,
}

impl Updater {
    pub fn new(current: &str, data_dir: &Path, repo: &str, on_change: Arc<dyn Fn() + Send + Sync>) -> Updater {
        let inner = UpdaterState { state: "idle".into(), ..Default::default() };
        Updater { current: current.into(), repo: repo.into(), folder: data_dir.join("updates"), inner: Arc::new(Mutex::new(inner)), on_change }
    }

    pub fn state(&self) -> String {
        self.inner.lock().unwrap().state.clone()
    }

    pub fn error(&self) -> String {
        self.inner.lock().unwrap().error.clone()
    }

    /// Новая версия, если она есть в релизах.
    pub fn available(&self) -> String {
        let s = self.inner.lock().unwrap();
        s.release.as_ref().filter(|r| is_newer(&r.version, &self.current)).map(|r| r.version.clone()).unwrap_or_default()
    }

    pub fn is_busy(&self) -> bool {
        BUSY.contains(&self.state().as_str())
    }

    pub fn snapshot(&self) -> Value {
        let available = self.available();
        let s = self.inner.lock().unwrap();
        json!({
            "version": self.current, "state": s.state, "latest": s.release.as_ref().map(|r| r.version.clone()).unwrap_or_default(),
            "available": available, "done": s.done, "total": s.total, "error": s.error,
        })
    }

    fn set(&self, state: &str, error: &str) {
        {
            let mut s = self.inner.lock().unwrap();
            s.state = state.into();
            s.error = error.into();
        }
        (self.on_change)();
    }

    pub async fn check(&self) {
        if self.is_busy() || self.state() == "ready" {
            return;
        }
        self.set("checking", "");
        let repo = self.repo.clone();
        match tokio::task::spawn_blocking(move || latest_release(&repo)).await {
            Ok(Ok(release)) => {
                self.inner.lock().unwrap().release = release;
                self.set(if self.available().is_empty() { "latest" } else { "available" }, "");
            }
            // Что бы ни случилось с GitHub, защита работать не перестаёт
            Ok(Err(e)) => self.set("error", &format!("{e:#}")),
            Err(e) => self.set("error", &e.to_string()),
        }
    }

    /// Начать загрузку в фоне. false — уже идёт, уже скачано или обновлять нечего.
    pub fn start(&self, install_after: bool) -> bool {
        if !can_update() {
            self.set("error", "агент запущен не из установщика — обновлять нечего");
            return false;
        }
        if self.is_busy() || self.available().is_empty() {
            return false;
        }
        let me = self.clone();
        if self.state() == "ready" {
            if install_after {
                tokio::spawn(async move { me.install(false).await.ok() });
            }
            return install_after;
        }
        tokio::spawn(async move { me.download_then(install_after).await });
        true
    }

    async fn download_then(&self, install_after: bool) {
        {
            let mut s = self.inner.lock().unwrap();
            s.done = 0;
            s.total = 0;
        }
        self.set("downloading", "");
        let (release, folder, inner) = (self.inner.lock().unwrap().release.clone(), self.folder.clone(), self.inner.clone());
        let Some(release) = release else { return };
        let result = tokio::task::spawn_blocking(move || {
            download(&release, &folder, &|done, total| {
                let mut s = inner.lock().unwrap(); // окно само опрашивает — без лишних сообщений серверу
                s.done = done;
                s.total = total;
            })
        })
        .await;
        match result {
            Ok(Ok(path)) => {
                self.inner.lock().unwrap().installer = Some(path);
                self.set("ready", "");
                if install_after {
                    let _ = self.install(false).await;
                }
            }
            Ok(Err(e)) => self.set("error", &format!("{e:#}")),
            Err(e) => self.set("error", &e.to_string()),
        }
    }

    /// Запустить установку скачанного. Установщик остановит агента и запустит уже новую версию.
    pub async fn install(&self, reopen_window: bool) -> Result<()> {
        let installer = {
            let s = self.inner.lock().unwrap();
            if s.state != "ready" {
                bail!("сначала скачайте обновление");
            }
            s.installer.clone().context("сначала скачайте обновление")?
        };
        self.set("installing", "");
        if reopen_window {
            let _ = std::fs::write(self.folder.join(REOPEN_FLAG), &self.current);
        }
        let folder = self.folder.clone();
        match tokio::task::spawn_blocking(move || install(&installer, &folder)).await? {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set("error", &format!("{e:#}"));
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://github.com/abdurohman-karim/deepsec/releases/download/v0.7.0/DeepSecSetup-0.7.0.exe";

    fn asset(name: &str, digest: &str, url: &str) -> Value {
        json!({"assets": [{"name": "notes.txt"}, {"name": name, "digest": digest, "browser_download_url": url}]})
    }

    #[test]
    fn versions() {
        assert!(is_newer("0.10.0", "0.9.9") && is_newer("0.7.0", "0.6.2"));
        assert!(!is_newer("0.6.2", "0.6.2") && !is_newer("0.5.9", "0.6.0"));
    }

    #[test]
    fn release_needs_installer_with_digest_from_our_repo() {
        let repo = "abdurohman-karim/deepsec";
        let r = release_from_json(&asset("DeepSecSetup-0.7.0.exe", "sha256:ABCD", URL), repo).unwrap();
        assert_eq!((r.version.as_str(), r.sha256.as_str()), ("0.7.0", "abcd"));
        assert!(release_from_json(&asset("DeepSecSetup-0.7.0.exe", "", URL), repo).is_none()); // без SHA-256 не ставим
        let evil = URL.replace("abdurohman-karim/deepsec", "someone/else");
        assert!(release_from_json(&asset("DeepSecSetup-0.7.0.exe", "sha256:ab", &evil), repo).is_none());
        assert!(release_from_json(&asset("DeepSecSetup-latest.exe", "sha256:ab", URL), repo).is_none());
    }

    #[test]
    fn reopen_flag_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("updates")).unwrap();
        std::fs::write(dir.path().join("updates").join(REOPEN_FLAG), "0.6.2").unwrap();
        assert_eq!(take_reopen_flag(dir.path()).as_deref(), Some("0.6.2"));
        assert!(take_reopen_flag(dir.path()).is_none());
    }

    #[tokio::test]
    async fn install_before_download_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let u = Updater::new("0.7.0", dir.path(), "abdurohman-karim/deepsec", Arc::new(|| {}));
        assert!(u.install(true).await.unwrap_err().to_string().contains("сначала скачайте"));
        assert_eq!(u.snapshot()["state"], "idle");
    }

    /// cargo test -- --ignored: настоящий релиз в GitHub виден и скачивается с совпавшим SHA-256.
    #[test]
    #[ignore]
    fn real_latest_release_downloads() {
        let release = latest_release("abdurohman-karim/deepsec").unwrap().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = download(&release, dir.path(), &|_, _| {}).unwrap();
        println!("{} -> {} ({} KB)", release.version, path.display(), std::fs::metadata(&path).unwrap().len() / 1024);
    }
}
