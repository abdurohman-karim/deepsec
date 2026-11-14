//! Правила: превращают события журнала безопасности Windows в инциденты (как deepsec/detector.py).

use std::collections::{HashMap, VecDeque};

use crate::config::Config;
use crate::incidents::{Incident, Kind, Severity};
use crate::winevent::WinEvent;

pub const FILE_SYSTEM_GUID: &str = "{0CCE921D-69AE-11D9-BED3-505054503030}";
pub const LOGON_GUID: &str = "{0CCE9215-69AE-11D9-BED3-505054503030}";
pub const AUDIT_POLICY_CHANGE_GUID: &str = "{0CCE922F-69AE-11D9-BED3-505054503030}";
/// Коды в поле AuditPolicyChanges события 4719: %%8448 «успех удалён», %%8450 «сбой удалён».
const AUDIT_REMOVED_CODES: [&str; 2] = ["%%8448", "%%8450"];
const SERVICE_DOMAINS: [&str; 3] = ["window manager", "font driver host", "nt authority"];
const LOCAL_IPS: [&str; 4] = ["", "-", "127.0.0.1", "::1"];
const LOGON_DEDUP_SECONDS: f64 = 15.0;

fn logon_type_name(t: &str) -> String {
    match t {
        "2" => "вход за компьютером",
        "3" => "сетевой вход",
        "7" => "разблокировка",
        "8" => "сетевой вход (открытый пароль)",
        "10" => "RDP",
        "11" => "вход по кэшу",
        other => other,
    }
    .to_string()
}

/// Регистр и разделители, как ntpath.normcase(ntpath.normpath()): сравнение путей без учёта регистра.
pub fn norm_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let unified = path.replace('/', "\\");
    let prefix_len = if unified.starts_with("\\\\") { 2 } else { 0 };
    let mut parts: Vec<&str> = Vec::new();
    for part in unified[prefix_len..].split('\\') {
        match part {
            "" | "." => continue,
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("{}{}", &unified[..prefix_len], parts.join("\\")).to_lowercase()
}

pub fn is_under(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{}\\", root.trim_end_matches('\\')))
}

/// В журнале PID записан как 0x1a2c.
pub fn parse_pid(value: &str) -> Option<u32> {
    let v = value.trim();
    match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => v.parse().ok(),
    }
}

fn account(ev: &WinEvent, prefix: &str) -> String {
    let user = ev.get(&format!("{prefix}UserName"));
    let domain = ev.get(&format!("{prefix}DomainName"));
    if !domain.is_empty() && domain != "-" { format!("{domain}\\{user}") } else { user.to_string() }
}

pub struct Detector {
    tdata: Vec<String>,
    decoys: Vec<String>,
    canary: String,
    self_pid: u32,
    alert_local_logons: bool,
    alert_network_logons: bool,
    failed_threshold: usize,
    failed_window: f64,
    failed: VecDeque<(f64, WinEvent)>,
    recent_logons: HashMap<(String, String), f64>,
    /// Когда последний раз видели чтение canary-файла самим агентом (самопроверка аудита).
    pub selftest_seen: f64,
}

impl Detector {
    pub fn new(cfg: &Config, self_pid: u32) -> Detector {
        Detector {
            tdata: cfg.tdata_dirs.iter().map(|p| norm_path(p)).collect(),
            decoys: cfg.decoy_dirs.iter().map(|p| norm_path(p)).collect(),
            canary: norm_path(&cfg.canary_file().to_string_lossy()),
            self_pid,
            alert_local_logons: cfg.alert_local_logons,
            alert_network_logons: cfg.alert_network_logons,
            failed_threshold: cfg.failed_logon_threshold,
            failed_window: cfg.failed_logon_window,
            failed: VecDeque::new(),
            recent_logons: HashMap::new(),
            selftest_seen: f64::NEG_INFINITY,
        }
    }

    /// now — монотонные секунды; is_trusted — можно ли этому exe читать tdata (подпись или закреплённый хэш).
    pub fn process(&mut self, ev: &WinEvent, now: f64, is_trusted: &mut dyn FnMut(&str) -> bool) -> Option<Incident> {
        match ev.event_id {
            4663 => self.file_access(ev, now, is_trusted),
            4624 => self.logon(ev, now),
            4625 => self.failed_logon(ev, now),
            4719 => self.audit_policy(ev),
            1102 => Some(
                Incident::new(Kind::LogCleared, Severity::Critical, "Журнал безопасности Windows очищен")
                    .detail("кто", account(ev, "Subject")),
            ),
            _ => None,
        }
    }

    fn file_access(&mut self, ev: &WinEvent, now: f64, is_trusted: &mut dyn FnMut(&str) -> bool) -> Option<Incident> {
        let raw_path = ev.get("ObjectName");
        let path = norm_path(raw_path);
        let pid = parse_pid(ev.get("ProcessId"));

        if path == self.canary {
            if pid == Some(self.self_pid) {
                self.selftest_seen = now;
            }
            return None;
        }
        let (kind, mut title) = if self.decoys.iter().any(|d| is_under(&path, d)) {
            (Kind::DecoyAccess, "Кто-то читает файлы-ловушку tdata".to_string())
        } else if self.tdata.iter().any(|d| is_under(&path, d)) {
            (Kind::TdataAccess, "Чужой процесс читает сессию Telegram".to_string())
        } else {
            return None;
        };

        let process = ev.get("ProcessName");
        if pid == Some(self.self_pid) || (!process.is_empty() && is_trusted(process)) {
            return None;
        }
        if pid == Some(4) || process.is_empty() {
            title.push_str(" (ядро/SMB — возможно, доступ по сети)");
        }
        let mut inc = Incident::new(kind, Severity::Critical, title).detail("пользователь", account(ev, "Subject"));
        inc.pid = pid;
        inc.process_path = (!process.is_empty()).then(|| process.to_string());
        inc.files = vec![raw_path.to_string()];
        inc.respond = true;
        Some(inc)
    }

    fn logon(&mut self, ev: &WinEvent, now: f64) -> Option<Incident> {
        let logon_type = ev.get("LogonType");
        let (user, domain) = (ev.get("TargetUserName"), ev.get("TargetDomainName"));
        let upper = user.to_uppercase();
        if user.is_empty()
            || user.ends_with('$')
            || SERVICE_DOMAINS.contains(&domain.to_lowercase().as_str())
            || upper.starts_with("DWM-")
            || upper.starts_with("UMFD-")
        {
            return None;
        }
        let ip = ev.get("IpAddress");
        let (kind, severity, title) = match logon_type {
            "10" => (Kind::RemoteLogon, Severity::Critical, "RDP-подключение к компьютеру"),
            "2" | "7" | "11" if self.alert_local_logons => (Kind::LocalLogon, Severity::Info, "Вход в Windows"),
            "3" | "8" if self.alert_network_logons && !LOCAL_IPS.contains(&ip) => {
                (Kind::RemoteLogon, Severity::Warning, "Сетевой вход в компьютер")
            }
            _ => return None,
        };
        // Один вход даёт пару событий (обычный и повышенный токен) — склеиваем
        let who = account(ev, "Target");
        let key = (logon_type.to_string(), who.to_lowercase());
        if now - self.recent_logons.get(&key).copied().unwrap_or(f64::NEG_INFINITY) < LOGON_DEDUP_SECONDS {
            return None;
        }
        self.recent_logons.insert(key, now);

        let mut inc = Incident::new(kind, severity, title).detail("учётка", who).detail("тип", logon_type_name(logon_type));
        if !LOCAL_IPS.contains(&ip) {
            inc = inc.detail("IP", ip);
        }
        let station = ev.get("WorkstationName");
        if !station.is_empty() && station != "-" {
            inc = inc.detail("компьютер", station);
        }
        Some(inc)
    }

    fn failed_logon(&mut self, ev: &WinEvent, now: f64) -> Option<Incident> {
        self.failed.push_back((now, ev.clone()));
        while self.failed.front().is_some_and(|(t, _)| now - t > self.failed_window) {
            self.failed.pop_front();
        }
        if self.failed.len() < self.failed_threshold {
            return None;
        }
        let attempts: Vec<WinEvent> = self.failed.drain(..).map(|(_, e)| e).collect();
        let sorted = |items: Vec<String>| {
            let mut set: Vec<String> = items.into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            set.retain(|s| !s.is_empty());
            set
        };
        let ips = sorted(attempts.iter().map(|e| e.get("IpAddress").to_string()).filter(|ip| !LOCAL_IPS.contains(&ip.as_str())).collect());
        let severity = if ips.is_empty() { Severity::Warning } else { Severity::Critical };
        Some(
            Incident::new(Kind::FailedLogons, severity, format!("Неудачные попытки входа: {}", attempts.len()))
                .detail("учётки", sorted(attempts.iter().map(|e| account(e, "Target")).collect()).join(", "))
                .detail("IP", if ips.is_empty() { "локально".to_string() } else { ips.join(", ") })
                .detail("тип", sorted(attempts.iter().map(|e| logon_type_name(e.get("LogonType"))).collect()).join(", ")),
        )
    }

    fn audit_policy(&self, ev: &WinEvent) -> Option<Incident> {
        let guid = ev.get("SubcategoryGuid").to_uppercase();
        let changes = ev.get("AuditPolicyChanges");
        if ![FILE_SYSTEM_GUID, LOGON_GUID].contains(&guid.as_str()) || !AUDIT_REMOVED_CODES.iter().any(|c| changes.contains(c)) {
            return None;
        }
        Some(
            Incident::new(Kind::AuditDisabled, Severity::Critical, "Кто-то отключил аудит, на котором держится защита")
                .detail("кто", account(ev, "Subject"))
                .detail("подкатегория", guid),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::winevent::{parse_event_xml, tests::event_xml};
    use std::collections::HashMap;

    pub const TDATA: &str = r"C:\Users\me\AppData\Roaming\Telegram Desktop\tdata";
    pub const DECOY: &str = r"C:\Users\me\AppData\Roaming\AyuGram Desktop\tdata";
    const SELF_PID: u32 = 0x500;
    const TELEGRAM: &str = r"C:\Users\me\AppData\Roaming\Telegram Desktop\Telegram.exe";
    const STEALER: &str = r"C:\Users\me\Downloads\crack.exe";

    pub fn cfg() -> Config {
        let env: HashMap<String, String> = [
            ("SERVER_URL", "ws://127.0.0.1:1/agent"),
            ("AGENT_TOKEN", "secret-token"),
            ("AGENT_NAME", "HOME-PC"),
            ("TDATA_DIRS", TDATA),
            ("DECOY_DIRS", DECOY),
            ("DATA_DIR", r"C:\ProgramData\DeepSec"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        Config::from_mapping(&env).unwrap()
    }

    fn run(d: &mut Detector, xml: String, now: f64) -> Option<Incident> {
        d.process(&parse_event_xml(&xml).unwrap(), now, &mut |p: &str| p == TELEGRAM)
    }

    fn read(path: &str, process: &str, pid: &str) -> String {
        event_xml(4663, &[("ObjectName", path), ("ProcessName", process), ("ProcessId", pid),
            ("SubjectUserName", "me"), ("SubjectDomainName", "PC"), ("AccessMask", "0x1")])
    }

    #[test]
    fn stealer_reading_key_datas_is_critical() {
        let mut d = Detector::new(&cfg(), SELF_PID);
        let inc = run(&mut d, read(&format!(r"{TDATA}\key_datas"), STEALER, "0x1a2c"), 0.0).unwrap();
        assert_eq!((inc.kind, inc.severity, inc.pid), (Kind::TdataAccess, Severity::Critical, Some(0x1A2C)));
        assert_eq!(inc.process_path.as_deref(), Some(STEALER));
        assert!(inc.respond);
    }

    #[test]
    fn paths_case_insensitive_and_prefix_safe() {
        let mut d = Detector::new(&cfg(), SELF_PID);
        assert!(run(&mut d, read(&format!(r"{}\D877F783D5D3EF8C\maps", TDATA.to_uppercase()), STEALER, "0x1"), 0.0).is_some());
        assert!(run(&mut d, read(&format!(r"{TDATA}_backup\key_datas"), STEALER, "0x1"), 0.0).is_none());
        assert!(run(&mut d, read(&format!(r"{TDATA}\key_datas"), TELEGRAM, "0x1"), 0.0).is_none());
    }

    #[test]
    fn decoy_smb_and_canary() {
        let mut d = Detector::new(&cfg(), SELF_PID);
        let decoy = run(&mut d, read(&format!(r"{DECOY}\key_datas"), STEALER, "0x2"), 0.0).unwrap();
        assert!(decoy.kind == Kind::DecoyAccess && decoy.respond);
        let smb = run(&mut d, read(&format!(r"{TDATA}\key_datas"), "", "0x4"), 0.0).unwrap();
        assert!(smb.pid == Some(4) && smb.process_path.is_none() && smb.title.contains("SMB"));
        let canary = r"C:\ProgramData\DeepSec\canary\selftest.bin";
        assert!(run(&mut d, read(canary, STEALER, "0x9"), 5.0).is_none());
        assert_eq!(d.selftest_seen, f64::NEG_INFINITY);
        assert!(run(&mut d, read(canary, r"C:\x\DeepSecAgent.exe", &format!("{SELF_PID:#x}")), 7.0).is_none());
        assert_eq!(d.selftest_seen, 7.0);
    }

    fn logon(t: &str, user: &str, domain: &str, ip: &str) -> String {
        event_xml(4624, &[("LogonType", t), ("TargetUserName", user), ("TargetDomainName", domain),
            ("IpAddress", ip), ("WorkstationName", "ATTACKER")])
    }

    #[test]
    fn logons() {
        let mut d = Detector::new(&cfg(), SELF_PID);
        let rdp = run(&mut d, logon("10", "me", "PC", "203.0.113.5"), 0.0).unwrap();
        assert!(rdp.kind == Kind::RemoteLogon && rdp.severity == Severity::Critical && rdp.details["IP"] == "203.0.113.5");
        assert!(run(&mut d, logon("2", "DWM-1", "Window Manager", "-"), 0.0).is_none());
        assert!(run(&mut d, logon("5", "SYSTEM", "NT AUTHORITY", "-"), 0.0).is_none());
        assert!(run(&mut d, logon("2", "PC$", "PC", "-"), 0.0).is_none());
        assert!(run(&mut d, logon("3", "me", "PC", "192.168.1.20"), 0.0).is_none()); // сетевые выключены
        assert!(run(&mut d, logon("2", "me", "PC", "-"), 100.0).is_some());
        assert!(run(&mut d, logon("2", "me", "PC", "-"), 101.0).is_none()); // повышенный токен того же входа
        assert!(run(&mut d, logon("2", "me", "PC", "-"), 160.0).is_some());
    }

    fn failed(ip: &str) -> String {
        event_xml(4625, &[("LogonType", "2"), ("TargetUserName", "me"), ("TargetDomainName", "PC"), ("IpAddress", ip)])
    }

    #[test]
    fn failed_logons() {
        let mut d = Detector::new(&cfg(), SELF_PID);
        assert!(run(&mut d, failed("-"), 0.0).is_none());
        assert!(run(&mut d, failed("-"), 1.0).is_none());
        let inc = run(&mut d, failed("-"), 2.0).unwrap();
        assert!(inc.kind == Kind::FailedLogons && inc.severity == Severity::Warning);
        assert!(run(&mut d, failed("-"), 3.0).is_none()); // счётчик сброшен

        let mut d = Detector::new(&cfg(), SELF_PID);
        run(&mut d, failed("-"), 0.0);
        run(&mut d, failed("-"), 1.0);
        assert!(run(&mut d, failed("-"), 302.0).is_none()); // вне окна не складываются

        let mut d = Detector::new(&cfg(), SELF_PID);
        run(&mut d, failed("203.0.113.5"), 0.0);
        run(&mut d, failed("203.0.113.5"), 1.0);
        let inc = run(&mut d, failed("203.0.113.5"), 2.0).unwrap();
        assert!(inc.severity == Severity::Critical && inc.details["IP"] == "203.0.113.5");
    }

    #[test]
    fn audit_policy() {
        let mut d = Detector::new(&cfg(), SELF_PID);
        let off = event_xml(4719, &[("SubcategoryGuid", &FILE_SYSTEM_GUID.to_lowercase()),
            ("AuditPolicyChanges", "%%8448, %%8450"), ("SubjectUserName", "evil"), ("SubjectDomainName", "PC")]);
        let inc = run(&mut d, off, 0.0).unwrap();
        assert!(inc.kind == Kind::AuditDisabled && inc.details["кто"] == "PC\\evil");
        let on = event_xml(4719, &[("SubcategoryGuid", FILE_SYSTEM_GUID), ("AuditPolicyChanges", "%%8449, %%8451")]);
        assert!(run(&mut d, on, 0.0).is_none());
    }

    #[test]
    fn norm_path_like_ntpath() {
        assert_eq!(norm_path(r"C:/Users/ME/./x/../tdata\"), r"c:\users\me\tdata");
        assert!(is_under(r"c:\a\b", r"c:\a") && !is_under(r"c:\ab", r"c:\a"));
    }
}
