//! Разбор XML событий журнала Windows (то, что отдаёт EvtRender).

use std::collections::HashMap;

use anyhow::{Result, bail};
use chrono::{DateTime, NaiveDateTime, Utc};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

#[derive(Clone, Debug)]
pub struct WinEvent {
    pub event_id: u32,
    pub record_id: u64,
    pub time: DateTime<Utc>,
    pub data: HashMap<String, String>,
}

impl WinEvent {
    pub fn get(&self, key: &str) -> &str {
        self.data.get(key).map(String::as_str).unwrap_or("")
    }
}

fn parse_time(value: &str) -> DateTime<Utc> {
    // «2026-11-03T10:15:30.1234567Z» — дробная часть до 7 знаков, берём микросекунды
    let (base, fraction) = value.trim_end_matches('Z').split_once('.').unwrap_or((value.trim_end_matches('Z'), "0"));
    let micros: u32 = format!("{:0<6}", &fraction[..fraction.len().min(6)]).parse().unwrap_or(0);
    NaiveDateTime::parse_from_str(base, "%Y-%m-%dT%H:%M:%S")
        .map(|t| t.and_utc() + chrono::Duration::microseconds(micros as i64))
        .unwrap_or_else(|_| Utc::now())
}

/// Поля EventData/Data[@Name], а для событий вроде 1102 — листья UserData.
pub fn parse_event_xml(xml: &str) -> Result<WinEvent> {
    let mut reader = Reader::from_str(xml);
    let (mut event_id, mut record_id, mut time) = (None, 0u64, None);
    let mut data = HashMap::new();
    let mut path: Vec<String> = Vec::new(); // локальные имена открытых элементов
    let mut data_name: Option<String> = None;
    let mut text = String::new();

    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_string();
                data_name = None;
                if name == "Data" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == "Name" {
                            data_name = Some(attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned());
                        }
                    }
                }
                path.push(name);
                text.clear();
            }
            Event::Empty(e) => {
                if e.local_name().as_ref() == "TimeCreated" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == "SystemTime" {
                            time = Some(parse_time(&attr.normalized_value(XmlVersion::Implicit1_0)?));
                        }
                    }
                }
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) => {
                // &amp; и прочие сущности внутри текста
                if let Some(ch) = r.resolve_char_ref()? {
                    text.push(ch);
                } else {
                    let name = r.xml10_content();
                    text.push_str(match name.as_ref() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    });
                }
            }
            Event::End(_) => {
                let name = path.pop().unwrap_or_default();
                let value = text.trim().to_string();
                let parent = path.last().map(String::as_str);
                match (name.as_str(), parent) {
                    ("EventID", Some("System")) => event_id = value.parse().ok(),
                    ("EventRecordID", Some("System")) => record_id = value.parse().unwrap_or(0),
                    ("Data", Some("EventData")) => {
                        if let Some(key) = data_name.take() {
                            data.insert(key, value);
                        }
                    }
                    _ if path.iter().any(|p| p == "UserData") && !value.is_empty() => {
                        data.entry(name).or_insert(value);
                    }
                    _ => {}
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let Some(event_id) = event_id else { bail!("в событии нет блока System/EventID") };
    Ok(WinEvent { event_id, record_id, time: time.unwrap_or_else(Utc::now), data })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn event_xml(event_id: u32, data: &[(&str, &str)]) -> String {
        let fields: String = data.iter().map(|(k, v)| format!(r#"<Data Name="{k}">{v}</Data>"#)).collect();
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{event_id}</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-11-03T10:15:30.1234567Z"/></System><EventData>{fields}</EventData></Event>"#
        )
    }

    #[test]
    fn parses_event_data() {
        let ev = parse_event_xml(&event_xml(4663, &[("ObjectName", r"C:\x\key_datas"), ("ProcessId", "0x10")])).unwrap();
        assert_eq!((ev.event_id, ev.record_id), (4663, 42));
        assert_eq!(ev.get("ObjectName"), r"C:\x\key_datas");
        assert_eq!(ev.get("Missing"), "");
        assert_eq!(ev.time.to_rfc3339(), "2026-11-03T10:15:30.123456+00:00");
    }

    #[test]
    fn escaped_text_and_user_data() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID><EventRecordID>7</EventRecordID><TimeCreated SystemTime="2026-11-03T10:15:30Z"/></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>evil &amp; co</SubjectUserName><SubjectDomainName>PC</SubjectDomainName></LogFileCleared></UserData></Event>"#;
        let ev = parse_event_xml(xml).unwrap();
        assert_eq!(ev.event_id, 1102);
        assert_eq!(ev.get("SubjectUserName"), "evil & co");
        assert_eq!(ev.get("SubjectDomainName"), "PC");
    }
}
