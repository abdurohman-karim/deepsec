//! Настройки агента (C:\ProgramData\DeepSec\.env) — тот же файл и те же ключи, что у Python-агента.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Каким exe и с какой цифровой подписью (O= или CN= сертификата) разрешено читать tdata.
pub const DEFAULT_TRUSTED: &str = "Telegram.exe=Telegram FZ-LLC|Telegram Messenger LLP;\
     Updater.exe=Telegram FZ-LLC|Telegram Messenger LLP;\
     MsMpEng.exe=Microsoft Corporation;\
     MpDefenderCoreService.exe=Microsoft Corporation";
pub const DEFAULT_UPDATE_REPO: &str = "abdurohman-karim/deepsec";

pub type Trusted = HashMap<String, BTreeSet<String>>;

pub fn default_data_dir() -> PathBuf {
    let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&base).join("DeepSec")
}

pub fn split_list(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn parse_flag(value: Option<&str>, default: bool) -> bool {
    match value.map(str::trim) {
        None | Some("") => default,
        Some(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

/// 'Telegram.exe=Org A|Org B;MsMpEng.exe=Microsoft Corporation' -> {'telegram.exe': {...}}
pub fn parse_trusted(spec: &str) -> Trusted {
    let mut result = Trusted::new();
    for item in split_list(Some(spec)) {
        let (name, signers) = item.split_once('=').unwrap_or((&item, ""));
        let set = signers.split('|').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
        result.insert(name.trim().to_lowercase(), set);
    }
    result
}

#[derive(Clone, Debug)]
pub struct Config {
    pub server_url: String,
    /// SHA-256 сертификата сервера (закреплён — подменить сервер нельзя).
    pub server_fingerprint: String,
    pub agent_token: String,
    pub agent_name: String,
    pub tdata_dirs: Vec<String>,
    pub decoy_dirs: Vec<String>,
    pub trusted: Trusted,
    pub data_dir: PathBuf,
    pub auto_kill: bool,
    pub auto_firewall: bool,
    pub auto_lock: bool,
    pub alert_local_logons: bool,
    pub alert_network_logons: bool,
    pub failed_logon_threshold: usize,
    pub failed_logon_window: f64,
    pub selftest_interval: u64,
    pub process_poll_interval: f64,
    pub update_repo: String,
}

impl Config {
    pub fn canary_file(&self) -> PathBuf {
        self.data_dir.join("canary").join("selftest.bin")
    }

    pub fn load() -> Result<Config> {
        let path = default_data_dir().join(".env");
        if !path.is_file() {
            bail!("Не найден {} — сначала запустите установщик (setup) от администратора", path.display());
        }
        Self::from_mapping(&read_env(&path)?)
    }

    pub fn from_mapping(env: &HashMap<String, String>) -> Result<Config> {
        let get = |k: &str| env.get(k).map(String::as_str).filter(|v| !v.is_empty());
        let mut missing: Vec<&str> =
            ["SERVER_URL", "AGENT_TOKEN", "TDATA_DIRS"].into_iter().filter(|k| get(k).is_none()).collect();
        if get("SERVER_URL").is_some_and(|u| u.starts_with("wss://")) && get("SERVER_FINGERPRINT").is_none() {
            missing.push("SERVER_FINGERPRINT");
        }
        if !missing.is_empty() {
            bail!("В .env не заданы: {}", missing.join(", "));
        }
        let num = |k: &str, d: f64| get(k).and_then(|v| v.parse::<f64>().ok()).unwrap_or(d);
        Ok(Config {
            server_url: get("SERVER_URL").unwrap().into(),
            server_fingerprint: get("SERVER_FINGERPRINT").unwrap_or("").into(),
            agent_token: get("AGENT_TOKEN").unwrap().into(),
            agent_name: get("AGENT_NAME").map(String::from).unwrap_or_else(computer_name),
            tdata_dirs: split_list(get("TDATA_DIRS")),
            decoy_dirs: split_list(get("DECOY_DIRS")),
            trusted: parse_trusted(get("TRUSTED_PROCESSES").unwrap_or(DEFAULT_TRUSTED)),
            data_dir: get("DATA_DIR").map(PathBuf::from).unwrap_or_else(default_data_dir),
            auto_kill: parse_flag(get("AUTO_KILL"), true),
            auto_firewall: parse_flag(get("AUTO_FIREWALL"), true),
            auto_lock: parse_flag(get("AUTO_LOCK"), false),
            alert_local_logons: parse_flag(get("ALERT_LOCAL_LOGONS"), true),
            alert_network_logons: parse_flag(get("ALERT_NETWORK_LOGONS"), false),
            failed_logon_threshold: num("FAILED_LOGON_THRESHOLD", 3.0) as usize,
            failed_logon_window: num("FAILED_LOGON_WINDOW", 300.0),
            selftest_interval: num("SELFTEST_INTERVAL", 600.0) as u64,
            process_poll_interval: num("PROCESS_POLL_INTERVAL", 3.0),
            update_repo: get("UPDATE_REPO").unwrap_or(DEFAULT_UPDATE_REPO).into(),
        })
    }
}

/// .env в формате python-dotenv: KEY=value, комментарии, необязательные кавычки. Обратные слэши без кавычек —
/// как есть: в путях Windows (C:\Users\…) это не escape-последовательности (dotenvy на них спотыкается).
pub fn parse_env(text: &str) -> Vec<(String, String)> {
    let mut env = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim();
        let value = match value.chars().next() {
            Some(q @ ('"' | '\'')) if value.len() >= 2 && value.ends_with(q) => {
                let inner = &value[1..value.len() - 1];
                if q == '"' { inner.replace("\\\"", "\"").replace("\\n", "\n") } else { inner.to_string() }
            }
            _ => value.split(" #").next().unwrap_or("").trim_end().to_string(), // комментарий в конце строки
        };
        env.push((key.trim().to_string(), value));
    }
    env
}

pub fn read_env(path: &Path) -> Result<HashMap<String, String>> {
    Ok(parse_env(&std::fs::read_to_string(path)?).into_iter().collect())
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn trusted_spec_is_parsed() {
        let t = parse_trusted("Telegram.exe=Telegram FZ-LLC|Telegram Messenger LLP; MsMpEng.exe=Microsoft Corporation");
        assert_eq!(t["telegram.exe"].len(), 2);
        assert!(t["msmpeng.exe"].contains("Microsoft Corporation"));
    }

    #[test]
    fn config_requires_keys() {
        let err = Config::from_mapping(&map(&[
            ("SERVER_URL", "wss://1.2.3.4:8443/agent"),
            ("AGENT_TOKEN", "t"),
            ("TDATA_DIRS", r"C:\t"),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("SERVER_FINGERPRINT"));
        let cfg = Config::from_mapping(&map(&[
            ("SERVER_URL", "wss://1.2.3.4:8443/agent"),
            ("SERVER_FINGERPRINT", "AB:CD"),
            ("AGENT_TOKEN", "t"),
            ("TDATA_DIRS", r"C:\a;C:\b"),
            ("AUTO_LOCK", "yes"),
            ("AGENT_NAME", "Work"),
        ]))
        .unwrap();
        assert_eq!(cfg.tdata_dirs, vec![r"C:\a", r"C:\b"]);
        assert!(cfg.auto_lock && cfg.auto_kill && cfg.agent_name == "Work");
        assert_eq!(cfg.update_repo, DEFAULT_UPDATE_REPO);
    }

    #[test]
    fn env_file_like_python_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        // Как пишет setup: пути Windows без кавычек, с пробелами и обратными слэшами
        std::fs::write(&path, "# комментарий\nSERVER_URL=wss://203.0.113.10:8444/agent\nAGENT_NAME=\"Мой ПК\"\n\
            TDATA_DIRS=C:\\Users\\me\\AppData\\Roaming\\Telegram Desktop\\tdata\nDECOY_DIRS=C:\\a\\tdata;C:\\b\\tdata\n").unwrap();
        let env = read_env(&path).unwrap();
        assert_eq!(env["SERVER_URL"], "wss://203.0.113.10:8444/agent");
        assert_eq!(env["AGENT_NAME"], "Мой ПК");
        assert_eq!(env["TDATA_DIRS"], r"C:\Users\me\AppData\Roaming\Telegram Desktop\tdata");
        assert_eq!(split_list(Some(&env["DECOY_DIRS"])), vec![r"C:\a\tdata", r"C:\b\tdata"]);
    }
}
