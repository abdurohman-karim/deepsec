//! Инцидент — общий формат агента и сервера. JSON совпадает с Python (deepsec/incidents.py): сервер
//! разбирает его через Incident.from_json.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    TdataAccess,
    DecoyAccess,
    RemoteLogon,
    LocalLogon,
    FailedLogons,
    LogCleared,
    AuditDisabled,
    RemoteTool,
    Selftest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub kind: Kind,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub details: BTreeMap<String, String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_path: Option<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    /// true — инцидент требует автоматической реакции (kill / firewall / завершение сеансов), если защита «взведена».
    #[serde(default)]
    pub respond: bool,
    #[serde(default)]
    pub session: Option<i64>,
    #[serde(default)]
    pub host: String,
    pub id: String,
    #[serde(with = "python_time")]
    pub time: DateTime<Utc>,
}

/// Время как у Python isoformat(): микросекунды и «+00:00» — сервер на Python 3.10 не понимает «Z»
/// и наносекунды в datetime.fromisoformat.
mod python_time {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(time: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&time.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw).map(|t| t.with_timezone(&Utc)).map_err(serde::de::Error::custom)
    }
}

impl Incident {
    pub fn new(kind: Kind, severity: Severity, title: impl Into<String>) -> Incident {
        Incident {
            kind,
            severity,
            title: title.into(),
            details: BTreeMap::new(),
            pid: None,
            process_path: None,
            files: Vec::new(),
            actions: Vec::new(),
            respond: false,
            session: None,
            host: String::new(),
            id: hex::encode(rand::random::<[u8; 3]>()),
            time: Utc::now(),
        }
    }

    pub fn detail(mut self, key: &str, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("инцидент всегда сериализуется")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_python_format() {
        let mut inc = Incident::new(Kind::TdataAccess, Severity::Critical, "t").detail("кто", "PC\\me");
        inc.pid = Some(5);
        inc.files.push("key_datas".into());
        let json = inc.to_json();
        assert_eq!(json["kind"], "tdata_access");
        assert_eq!(json["severity"], "CRITICAL");
        assert_eq!(json["id"].as_str().unwrap().len(), 6);
        let time = json["time"].as_str().unwrap();
        assert!(time.ends_with("+00:00") && time.len() == "2026-11-03T10:15:30.123456+00:00".len(), "{time}");
        let back: Incident = serde_json::from_value(json).unwrap();
        assert_eq!(back.time.timestamp_micros(), inc.time.timestamp_micros());
        assert_eq!(back.id, inc.id);
    }

    #[test]
    fn reads_python_incident() {
        let raw = r#"{"kind": "decoy_access", "severity": "WARNING", "title": "x", "details": {},
            "pid": null, "process_path": null, "files": [], "actions": [], "respond": false,
            "session": null, "host": "", "id": "abc123", "time": "2026-11-03T10:15:30.123456+00:00"}"#;
        let inc: Incident = serde_json::from_str(raw).unwrap();
        assert_eq!(inc.kind, Kind::DecoyAccess);
        assert_eq!(inc.severity, Severity::Warning);
    }
}
