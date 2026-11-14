//! Состояние, переживающее перезапуск, журнал инцидентов и очередь неотправленных сообщений.
//! Файлы те же, что у Python-агента (state.json, incidents.jsonl, outbox.json) — обновление их подхватывает.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::incidents::Incident;

fn write_json(path: &Path, data: &impl Serialize) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(data)?)?;
    fs::rename(tmp, path)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentState {
    pub armed: bool,
    pub isolated: bool,
    /// Имя правила брандмауэра -> путь exe.
    pub blocked: BTreeMap<String, String>,
    /// SHA-256 -> путь exe (для показа).
    pub trusted_hashes: BTreeMap<String, String>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Default for AgentState {
    fn default() -> Self {
        AgentState { armed: true, isolated: false, blocked: BTreeMap::new(), trusted_hashes: BTreeMap::new(), path: None }
    }
}

impl AgentState {
    pub fn load(path: &Path) -> AgentState {
        let mut state = match fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|e| {
                log::error!("{} повреждён ({e}) — начинаю с настроек по умолчанию", path.display());
                AgentState::default()
            }),
            Err(_) => AgentState::default(),
        };
        state.path = Some(path.to_path_buf());
        state
    }

    pub fn save(&self) {
        if let Some(path) = &self.path
            && let Err(e) = write_json(path, self)
        {
            log::error!("Не удалось сохранить {}: {e}", path.display());
        }
    }
}

pub struct Journal {
    path: Option<PathBuf>,
    items: VecDeque<Incident>,
    size: usize,
}

impl Journal {
    pub fn new(path: Option<PathBuf>, size: usize) -> Journal {
        let mut items = VecDeque::with_capacity(size);
        if let Some(raw) = path.as_ref().and_then(|p| fs::read_to_string(p).ok()) {
            // Хвост журнала — чтобы кнопки под старыми уведомлениями работали после перезапуска
            for line in raw.lines().rev().take(size).collect::<Vec<_>>().into_iter().rev() {
                if let Ok(inc) = serde_json::from_str::<Incident>(line) {
                    items.push_back(inc);
                }
            }
        }
        Journal { path, items, size }
    }

    pub fn add(&mut self, incident: &Incident) {
        if self.items.len() == self.size {
            self.items.pop_front();
        }
        self.items.push_back(incident.clone());
        let Some(path) = &self.path else { return };
        let line = serde_json::to_string(incident).expect("инцидент сериализуется");
        let result = fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = result {
            log::error!("Не удалось записать инцидент в журнал: {e}");
        }
    }

    pub fn get(&self, id: &str) -> Option<&Incident> {
        self.items.iter().rev().find(|i| i.id == id)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct OutboxItem {
    key: String,
    message: Value,
}

/// Сообщения для сервера, которые ещё не подтверждены. Хранятся на диске: тревога о краже дойдёт до сервера,
/// даже если сети не было, а ПК успели перезагрузить.
pub struct Outbox {
    path: Option<PathBuf>,
    limit: usize,
    items: Vec<OutboxItem>,
}

impl Outbox {
    pub fn new(path: Option<PathBuf>, limit: usize) -> Outbox {
        let mut items: Vec<OutboxItem> = path
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        let excess = items.len().saturating_sub(limit);
        items.drain(..excess);
        Outbox { path, limit, items }
    }

    pub fn add(&mut self, key: &str, message: Value) {
        self.items.push(OutboxItem { key: key.into(), message });
        let excess = self.items.len().saturating_sub(self.limit);
        self.items.drain(..excess);
        self.save();
    }

    pub fn ack(&mut self, key: &str) {
        let before = self.items.len();
        self.items.retain(|i| i.key != key);
        if self.items.len() != before {
            self.save();
        }
    }

    pub fn items(&self) -> Vec<(String, Value)> {
        self.items.iter().map(|i| (i.key.clone(), i.message.clone())).collect()
    }

    fn save(&self) {
        if let Some(path) = &self.path
            && let Err(e) = write_json(path, &self.items)
        {
            log::error!("Не удалось сохранить outbox: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incidents::{Kind, Severity};
    use serde_json::json;

    #[test]
    fn state_roundtrip_and_python_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, r#"{"armed": false, "isolated": false, "blocked": {}, "trusted_hashes": {}, "extra": 1}"#).unwrap();
        let mut state = AgentState::load(&path);
        assert!(!state.armed);
        state.blocked.insert("DeepSec-Block-1".into(), r"C:\x.exe".into());
        state.save();
        assert_eq!(AgentState::load(&path).blocked["DeepSec-Block-1"], r"C:\x.exe");
        assert!(AgentState::load(&dir.path().join("missing.json")).armed);
    }

    #[test]
    fn outbox_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.json");
        let mut box_ = Outbox::new(Some(path.clone()), 2);
        for key in ["a", "b", "c"] {
            box_.add(key, json!({"n": key}));
        }
        box_.ack("b");
        assert_eq!(Outbox::new(Some(path), 200).items(), vec![("c".to_string(), json!({"n": "c"}))]);
    }

    #[test]
    fn journal_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incidents.jsonl");
        let mut journal = Journal::new(Some(path.clone()), 300);
        let inc = Incident::new(Kind::TdataAccess, Severity::Critical, "t");
        journal.add(&inc);
        assert_eq!(Journal::new(Some(path), 300).get(&inc.id).unwrap().title, "t");
    }
}
