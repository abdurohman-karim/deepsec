//! Установка, удаление и диагностика (как deepsec/setup_win.py). Запускается от администратора:
//! из установщика — `DeepSecAgent.exe setup --yes --pause --server … --fingerprint … --token …`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::{self, DEFAULT_TRUSTED, default_data_dir, parse_trusted, split_list};
use crate::protocol::{AGENT_PATH, normalize_fingerprint};
use crate::state::AgentState;
use crate::trust::{parse_subject, signer_matches};
use crate::{VERSION, response, update, win, winacl};

pub const TASK_NAME: &str = "DeepSec Agent";
const DEFAULT_PORT: &str = "8443";
/// Форки Telegram, которые ищут стилеры. Если вы ими не пользуетесь — любое чтение их tdata стопроцентно чужое.
const DECOY_APPS: [&str; 3] = ["AyuGram Desktop", "Kotatogram Desktop", "64Gram Desktop"];

const PS_REGISTER_TASK: &str = r#"
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute $env:DEEPSEC_EXE -Argument $env:DEEPSEC_ARGS -WorkingDirectory $env:DEEPSEC_WORKDIR
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $env:DEEPSEC_TASK -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $env:DEEPSEC_TASK
"#;

#[derive(Default)]
pub struct SetupOptions {
    pub server: String,
    pub port: String,
    pub fingerprint: String,
    pub token: String,
    pub name: String,
    /// Без вопросов, ответы по умолчанию (так запускает установщик).
    pub yes: bool,
}

/// .env как упорядоченный список — порядок ключей сохраняется при перезаписи.
pub type Env = Vec<(String, String)>;

fn get<'a>(env: &'a Env, key: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

fn set(env: &mut Env, key: &str, value: String) {
    match env.iter_mut().find(|(k, _)| k == key) {
        Some(entry) => entry.1 = value,
        None => env.push((key.into(), value)),
    }
}

fn remove(env: &mut Env, key: &str) {
    env.retain(|(k, _)| k != key);
}

fn input(prompt: &str) -> String {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn ask(prompt: &str, default: bool, opts: &SetupOptions) -> bool {
    if opts.yes {
        println!("{prompt} → {}", if default { "да" } else { "нет" });
        return default;
    }
    let answer = input(&format!("{prompt} [{}] ", if default { "Y/n" } else { "y/N" })).to_lowercase();
    if answer.is_empty() { default } else { matches!(answer.as_str(), "y" | "yes" | "д" | "да") }
}

pub fn load_env(path: &Path) -> Env {
    let Ok(iter) = dotenvy::from_path_iter(path) else { return Env::new() };
    iter.flatten().filter(|(_, v)| !v.is_empty()).collect()
}

/// Сменить только порт в прежнем SERVER_URL (IPv6 — в квадратных скобках).
pub fn with_port(url: &str, port: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("wss", url));
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let host = if authority.starts_with('[') {
        authority.split_once(']').map_or(authority.to_string(), |(h, _)| format!("{h}]"))
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h).to_string()
    };
    format!("{scheme}://{host}:{port}/{path}")
}

/// Параметры подключения: из флагов (перекрывают прежние), из старого .env или вопросом в консоли.
pub fn server_settings(existing: &Env, opts: &SetupOptions) -> Result<Env> {
    let mut merged = existing.clone();
    let mut changed = false;
    let port = if opts.port.trim().is_empty() { DEFAULT_PORT } else { opts.port.trim() };
    if !opts.server.trim().is_empty() {
        set(&mut merged, "SERVER_URL", format!("wss://{}:{port}{AGENT_PATH}", opts.server.trim()));
        changed = true;
    } else if !opts.port.trim().is_empty() && let Some(url) = get(existing, "SERVER_URL") {
        // Обновление, где адрес оставили пустым, а порт ввели: меняем только порт, иначе он молча потеряется
        set(&mut merged, "SERVER_URL", with_port(url, opts.port.trim()));
        changed = true;
    }
    for (value, key) in [(&opts.fingerprint, "SERVER_FINGERPRINT"), (&opts.token, "AGENT_TOKEN"), (&opts.name, "AGENT_NAME")] {
        if !value.trim().is_empty() {
            let value = if key == "SERVER_FINGERPRINT" { normalize_fingerprint(value) } else { value.trim().to_string() };
            set(&mut merged, key, value);
            changed = true;
        }
    }
    // Повторная настройка из меню «Пуск»: показываем, куда агент подключается, — иначе неверный адрес
    // или порт из первой установки остался бы навсегда
    if !changed && !opts.yes && let Some(url) = get(&merged, "SERVER_URL") {
        println!("\nСейчас агент подключается к {url}");
        if !ask("Оставить этот сервер?", true, opts) {
            for key in ["SERVER_URL", "SERVER_FINGERPRINT", "AGENT_TOKEN"] {
                remove(&mut merged, key);
            }
        }
    }
    let missing: Vec<&str> = ["SERVER_URL", "SERVER_FINGERPRINT", "AGENT_TOKEN"].into_iter().filter(|k| get(&merged, k).is_none()).collect();
    if !missing.is_empty() && opts.yes {
        bail!("не заданы данные сервера: {}. Их печатает ./deploy.sh на сервере", missing.join(", "));
    }
    if !missing.is_empty() {
        println!("\nДанные сервера показал ./deploy.sh при выкладке (их же можно посмотреть в .env на сервере).");
    }
    if get(&merged, "SERVER_URL").is_none() {
        let host = input("Адрес сервера (IP или домен): ");
        let typed = input(&format!("Порт агентов [{port}]: "));
        set(&mut merged, "SERVER_URL", format!("wss://{host}:{}{AGENT_PATH}", if typed.is_empty() { port } else { &typed }));
    }
    if get(&merged, "SERVER_FINGERPRINT").is_none() {
        set(&mut merged, "SERVER_FINGERPRINT", normalize_fingerprint(&input("SHA-256 отпечаток сертификата сервера: ")));
    }
    if get(&merged, "AGENT_TOKEN").is_none() {
        set(&mut merged, "AGENT_TOKEN", input("AGENT_TOKEN: "));
    }
    if get(&merged, "AGENT_NAME").is_none() {
        set(&mut merged, "AGENT_NAME", config::computer_name());
    }
    Ok(merged)
}

fn appdata() -> PathBuf {
    PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
}

/// tdata обычного Telegram и портативного (рядом с запущенным Telegram.exe).
pub fn find_tdata() -> Vec<PathBuf> {
    let mut candidates = vec![appdata().join("Telegram Desktop").join("tdata")];
    for p in win::processes() {
        if p.name.eq_ignore_ascii_case("telegram.exe")
            && let Some(exe) = win::exe_path(p.pid)
            && let Some(dir) = Path::new(&exe).parent()
        {
            candidates.push(dir.join("tdata"));
        }
    }
    let mut found: Vec<PathBuf> = Vec::new();
    for c in candidates {
        if c.is_dir() {
            let c = std::fs::canonicalize(&c).map(|p| PathBuf::from(p.to_string_lossy().trim_start_matches(r"\\?\"))).unwrap_or(c);
            if !found.iter().any(|f| f.to_string_lossy().eq_ignore_ascii_case(&c.to_string_lossy())) {
                found.push(c);
            }
        }
    }
    found
}

fn create_decoy(tdata: &Path) -> Result<()> {
    let account = tdata.join("D877F783D5D3EF8C");
    std::fs::create_dir_all(&account)?;
    for (path, size) in [(tdata.join("key_datas"), 328), (tdata.join("D877F783D5D3EF8Cs"), 1100), (tdata.join("settingss"), 700), (account.join("maps"), 400)] {
        let mut data = b"TDF$".to_vec();
        data.extend((0..size).map(|_| rand::random::<u8>()));
        std::fs::write(path, data)?;
    }
    Ok(())
}

/// Ваш Telegram.exe подписан тем, кому мы доверяем? Иначе агент убьёт сам Telegram.
/// opts = None — только показать (для check), без вопросов. Возвращает издателей, которых добавить в доверенные.
fn check_telegram_signatures(tdata_dirs: &[PathBuf], trusted: &config::Trusted, opts: Option<&SetupOptions>) -> Vec<String> {
    let mut extra = Vec::new();
    for tdata in tdata_dirs {
        let exe = tdata.parent().map(|p| p.join("Telegram.exe")).unwrap_or_default();
        if !exe.is_file() {
            continue;
        }
        let sig = win::read_signature(&exe.to_string_lossy());
        let org = parse_subject(&sig.subject).get("O").cloned().unwrap_or_default();
        println!("  {}: подпись {}, издатель {}", exe.display(), sig.status, if org.is_empty() { "—" } else { &org });
        let allowed = trusted.get("telegram.exe").cloned().unwrap_or_default();
        if sig.status != "Valid" {
            println!("  ⚠️  ПОДПИСЬ НЕВАЛИДНА. Это может быть подменённый Telegram.exe — переустановите с telegram.org!");
        } else if !signer_matches(&sig.subject, &allowed) {
            match opts {
                None => println!("  ⚠️  Издатель «{org}» не в списке доверенных — запустите setup, он предложит добавить"),
                Some(opts) if !org.is_empty() && ask(&format!("  Издатель «{org}» не в списке доверенных. Добавить?"), true, opts) => extra.push(org),
                _ => {}
            }
        }
    }
    extra
}

fn write_env(path: &Path, mut env: Env, tdata: &[PathBuf], decoys: &[PathBuf], extra_signers: &[String]) -> Result<()> {
    let join = |dirs: &[PathBuf]| dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join(";");
    set(&mut env, "TDATA_DIRS", join(tdata));
    set(&mut env, "DECOY_DIRS", join(decoys));
    if !extra_signers.is_empty() {
        let mut trusted = parse_trusted(get(&env, "TRUSTED_PROCESSES").unwrap_or(DEFAULT_TRUSTED));
        for name in ["telegram.exe", "updater.exe"] {
            trusted.entry(name.into()).or_default().extend(extra_signers.iter().cloned());
        }
        let mut names: Vec<_> = trusted.into_iter().collect();
        names.sort();
        let spec = names.iter().map(|(n, s)| format!("{n}={}", s.iter().cloned().collect::<Vec<_>>().join("|"))).collect::<Vec<_>>().join(";");
        set(&mut env, "TRUSTED_PROCESSES", spec);
    }
    let text: String = env.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    std::fs::write(path, text)?;
    Ok(())
}

fn run_checked(program: &str, args: &[&str]) -> Result<()> {
    let output = win::run_hidden(program, args)?;
    if !output.status.success() {
        bail!("{program}: {}", win::output_text(&output));
    }
    Ok(())
}

pub fn setup(opts: &SetupOptions) -> Result<i32> {
    if !win::is_admin() {
        println!("Запустите от имени администратора.");
        return Ok(1);
    }
    let exe = win::own_exe();
    let workdir = Path::new(&exe).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let home = std::env::var("USERPROFILE").unwrap_or_default().to_lowercase();
    if !home.is_empty() && exe.to_lowercase().starts_with(&home) {
        println!("⚠️  Агент лежит в папке пользователя. Он работает от SYSTEM, поэтому вирус без прав\n   администратора сможет подменить его и получить SYSTEM. Рекомендуется C:\\Program Files\\DeepSec.");
        if !ask("Продолжить всё равно?", false, opts) {
            return Ok(1);
        }
    }
    let data_dir = default_data_dir();
    let env_path = data_dir.join(".env");
    let existing = load_env(&env_path);
    let connection = server_settings(&existing, opts)?; // сначала — чтобы не настраивать аудит зря

    println!("1/6 Ищу tdata…");
    let tdata_dirs = find_tdata();
    if tdata_dirs.is_empty() {
        bail!("tdata не найдена. Запустите Telegram Desktop и повторите (меню «Пуск» → «Настроить DeepSec»)");
    }
    for t in &tdata_dirs {
        println!("  {}", t.display());
    }
    let trusted = parse_trusted(get(&existing, "TRUSTED_PROCESSES").unwrap_or(DEFAULT_TRUSTED));
    let extra_signers = check_telegram_signatures(&tdata_dirs, &trusted, Some(opts));

    println!("2/6 Готовлю папку данных (доступ только SYSTEM и администраторам)…");
    let canary_dir = data_dir.join("canary");
    std::fs::create_dir_all(&canary_dir)?;
    run_checked("icacls", &[&data_dir.to_string_lossy(), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])?;

    println!("3/6 Создаю ловушки…");
    let ours: Vec<String> = split_list(get(&existing, "DECOY_DIRS")).into_iter().map(|d| d.to_lowercase()).collect();
    let mut decoys = Vec::new();
    for app in DECOY_APPS {
        let root = appdata().join(app);
        let decoy = root.join("tdata");
        if root.exists() && !ours.contains(&decoy.to_string_lossy().to_lowercase()) {
            // Папка есть, но создавали её не мы — это настоящий клиент, его tdata трогать нельзя
            println!("  пропускаю {} — похоже, вы пользуетесь этим клиентом", root.display());
            continue;
        }
        if !decoy.join("key_datas").exists() {
            create_decoy(&decoy)?;
        }
        println!("  {}", decoy.display());
        decoys.push(decoy);
    }

    println!("4/6 Включаю аудит Windows и правила аудита на файлах…");
    winacl::enable_audit_policy()?;
    for t in &tdata_dirs {
        winacl::protect_tdata(t)?;
    }
    for target in decoys.iter().chain(std::iter::once(&canary_dir)) {
        winacl::add_read_audit(target, true)?;
    }
    std::fs::write(canary_dir.join("selftest.bin"), rand::random::<[u8; 32]>())?;

    println!("5/6 Настройки…");
    write_env(&env_path, connection, &tdata_dirs, &decoys, &extra_signers)?;
    let state_path = data_dir.join("state.json");
    if !state_path.exists() {
        let mut state = AgentState::load(&state_path);
        state.armed = ask("Сразу включить авто-реакцию (убивать нарушителей)? Иначе — только уведомления", true, opts);
        state.save();
    }

    println!("6/6 Регистрирую задачу планировщика (запуск от SYSTEM при старте Windows)…");
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PS_REGISTER_TASK])
        .env("DEEPSEC_EXE", &exe)
        .env("DEEPSEC_ARGS", "run")
        .env("DEEPSEC_WORKDIR", &workdir)
        .env("DEEPSEC_TASK", TASK_NAME)
        .creation_flags(win::CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        bail!("задача планировщика: {}", win::output_text(&output));
    }
    println!("\n✅ Готово. Агент запущен; лог: {}.\n   В боте должен появиться компьютер — откройте его и нажмите «🧪 Самопроверка».", data_dir.join("agent.log").display());
    Ok(0)
}

/// Убирает всё, что сделал setup: задачу, правила брандмауэра, изоляцию, ловушки, папку данных.
/// Политика аудита Windows остаётся — она безвредна, а её прежнее состояние неизвестно.
pub fn uninstall() -> Result<i32> {
    if !win::is_admin() {
        println!("Запустите от имени администратора.");
        return Ok(1);
    }
    let _ = win::run_hidden("schtasks", &["/End", "/TN", TASK_NAME]);
    let _ = win::run_hidden("schtasks", &["/Delete", "/F", "/TN", TASK_NAME]);
    let _ = win::run_hidden("schtasks", &["/Delete", "/F", "/TN", update::TASK_NAME]);
    let data_dir = default_data_dir();
    let state = AgentState::load(&data_dir.join("state.json"));
    if state.isolated {
        match response::unisolate() {
            Ok(()) => println!("Сеть восстановлена"),
            Err(e) => println!("⚠️  Не удалось снять изоляцию: {e:#}"),
        }
    }
    for rule in state.blocked.keys() {
        let _ = response::unblock(rule);
    }
    for decoy in split_list(get(&load_env(&data_dir.join(".env")), "DECOY_DIRS")) {
        // Ловушки создавал setup — вместе с папкой «клиента», если в ней больше ничего нет
        let _ = std::fs::remove_dir_all(&decoy);
        if let Some(parent) = Path::new(&decoy).parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
    let _ = std::fs::remove_dir_all(&data_dir);
    println!("DeepSec удалён с этого компьютера.");
    Ok(0)
}

pub fn check() -> Result<i32> {
    println!("DeepSec Agent {VERSION}");
    println!("tdata:");
    let tdata = find_tdata();
    for t in &tdata {
        println!("  {}", t.display());
    }
    let env_path = default_data_dir().join(".env");
    let env = load_env(&env_path);
    println!("Подписи Telegram.exe:");
    check_telegram_signatures(&tdata, &parse_trusted(get(&env, "TRUSTED_PROCESSES").unwrap_or(DEFAULT_TRUSTED)), None);
    if env.is_empty() {
        println!("Нет {} (или нет прав его прочитать) — setup ещё не выполнялся", env_path.display());
    } else {
        println!("Сервер: {}", get(&env, "SERVER_URL").unwrap_or("—"));
        let decoys = split_list(get(&env, "DECOY_DIRS"));
        println!("Ловушки: {}", if decoys.is_empty() { "нет".into() } else { decoys.join(", ") });
    }
    Ok(0)
}

/// `DeepSecAgent.exe update`: проверить и поставить новую версию из консоли (от администратора).
pub fn update_console() -> Result<i32> {
    if !win::is_admin() {
        println!("Запустите от имени администратора — или обновите из окна DeepSec, там права не нужны.");
        return Ok(1);
    }
    let cfg = config::Config::load()?;
    println!("Сейчас стоит {VERSION}. Проверяю релизы GitHub…");
    let release = update::latest_release(&cfg.update_repo)?.context("в релизах GitHub нет установщика с контрольной суммой")?;
    if !update::is_newer(&release.version, VERSION) {
        println!("Уже последняя версия ({VERSION})");
        return Ok(0);
    }
    let folder = cfg.data_dir.join("updates");
    let installer = update::download(&release, &folder, &|done, total| {
        if total > 0 {
            print!("\r  скачиваю {}%", done * 100 / total);
            let _ = std::io::stdout().flush();
        }
    })?;
    println!("\n{VERSION} → {}: установщик скачан, SHA-256 совпал, ставлю. Агент перезапустится примерно через минуту", release.version);
    update::install(&installer, &folder)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn installer_flags_build_connection() {
        let opts = SetupOptions { server: " 203.0.113.10 ".into(), port: "8444".into(), fingerprint: "AB:CD:EF".into(), token: " tok ".into(), yes: true, ..Default::default() };
        let e = server_settings(&Env::new(), &opts).unwrap();
        assert_eq!(get(&e, "SERVER_URL"), Some("wss://203.0.113.10:8444/agent"));
        assert_eq!((get(&e, "SERVER_FINGERPRINT"), get(&e, "AGENT_TOKEN")), (Some("abcdef"), Some("tok")));
        assert!(get(&e, "AGENT_NAME").is_some()); // по умолчанию — имя компьютера
    }

    #[test]
    fn upgrade_keeps_settings_and_can_change_only_the_port() {
        let old = env(&[("SERVER_URL", "wss://203.0.113.10:8443/agent"), ("SERVER_FINGERPRINT", "aa"), ("AGENT_TOKEN", "t"), ("AGENT_NAME", "Home")]);
        assert_eq!(server_settings(&old, &SetupOptions { yes: true, ..Default::default() }).unwrap(), old);
        let port_only = server_settings(&old, &SetupOptions { port: " 8444 ".into(), yes: true, ..Default::default() }).unwrap();
        assert_eq!(get(&port_only, "SERVER_URL"), Some("wss://203.0.113.10:8444/agent"));
        assert_eq!(with_port("wss://[2001:db8::1]:8443/agent", "8444"), "wss://[2001:db8::1]:8444/agent");
    }

    #[test]
    fn installer_without_server_data_fails_clearly() {
        let err = server_settings(&Env::new(), &SetupOptions { server: "203.0.113.10".into(), yes: true, ..Default::default() }).unwrap_err();
        assert!(err.to_string().contains("SERVER_FINGERPRINT, AGENT_TOKEN"));
    }
}
