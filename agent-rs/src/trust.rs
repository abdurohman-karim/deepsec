//! Можно ли доверять процессу: имя exe + валидная подпись нужного издателя или закреплённый SHA-256.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::config::Trusted;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// Valid, NotSigned, HashMismatch, Error…
    pub status: String,
    /// «CN=…, O=…, C=…» подписавшего сертификата.
    pub subject: String,
}

/// 'CN=Telegram FZ-LLC, O="Foo, Inc.", C=AE' -> {CN: …, O: 'Foo, Inc.', C: AE}; первое значение ключа выигрывает.
pub fn parse_subject(subject: &str) -> HashMap<String, String> {
    let mut parts = HashMap::new();
    let chars: Vec<char> = subject.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && (chars[i] == ' ' || chars[i] == ',') {
            i += 1;
        }
        let start = i;
        while i < chars.len() && chars[i] != '=' && chars[i] != ',' {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            continue;
        }
        let key: String = chars[start..i].iter().collect::<String>().trim().to_uppercase();
        i += 1;
        while i < chars.len() && chars[i] == ' ' {
            i += 1;
        }
        let mut value = String::new();
        if i < chars.len() && chars[i] == '"' {
            i += 1;
            while i < chars.len() {
                if chars[i] == '"' {
                    if chars.get(i + 1) == Some(&'"') {
                        value.push('"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                value.push(chars[i]);
                i += 1;
            }
            while i < chars.len() && chars[i] != ',' {
                i += 1;
            }
        } else {
            while i < chars.len() && chars[i] != ',' {
                value.push(chars[i]);
                i += 1;
            }
            value = value.trim().to_string();
        }
        if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
            parts.entry(key).or_insert(value);
        }
    }
    parts
}

pub fn signer_matches(subject: &str, allowed: &BTreeSet<String>) -> bool {
    let parts = parse_subject(subject);
    ["O", "CN"].iter().any(|k| parts.get(*k).is_some_and(|v| allowed.contains(v)))
}

pub fn sha256_file(path: &str) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub type SignatureReader = Box<dyn Fn(&str) -> Signature + Send + Sync>;

pub struct TrustChecker {
    trusted: Trusted,
    reader: SignatureReader,
    cache: HashMap<(String, SystemTime, u64), bool>,
}

impl TrustChecker {
    pub fn new(trusted: Trusted, reader: SignatureReader) -> TrustChecker {
        TrustChecker { trusted, reader, cache: HashMap::new() }
    }

    pub fn invalidate(&mut self) {
        self.cache.clear();
    }

    /// pinned — SHA-256 программ, которым владелец доверил читать tdata из бота.
    pub fn is_trusted(&mut self, path: &str, pinned: &BTreeSet<String>) -> bool {
        if path.is_empty() {
            return false;
        }
        let name = path.rsplit(['\\', '/']).next().unwrap_or(path).to_lowercase();
        let allowed = self.trusted.get(&name).filter(|a| !a.is_empty());
        // Самый частый случай для стилера: имени нет в белом списке — решаем мгновенно
        if allowed.is_none() && pinned.is_empty() {
            return false;
        }
        let Ok(meta) = std::fs::metadata(path) else { return false };
        let key = (path.to_lowercase(), meta.modified().unwrap_or(SystemTime::UNIX_EPOCH), meta.len());
        if let Some(&cached) = self.cache.get(&key) {
            return cached;
        }
        let mut ok = false;
        if let Some(allowed) = allowed {
            let sig = (self.reader)(path);
            ok = sig.status == "Valid" && signer_matches(&sig.subject, allowed);
        }
        if !ok && !pinned.is_empty() {
            ok = sha256_file(path).is_ok_and(|h| pinned.contains(&h));
        }
        self.cache.insert(key, ok);
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_trusted;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn subject_with_quoted_commas() {
        let parts = parse_subject(r#"CN=Telegram FZ-LLC, O="Telegram, FZ-LLC", L=Dubai, C=AE"#);
        assert_eq!(parts["CN"], "Telegram FZ-LLC");
        assert_eq!(parts["O"], "Telegram, FZ-LLC");
        assert_eq!((parts["L"].as_str(), parts["C"].as_str()), ("Dubai", "AE"));
        let ms: BTreeSet<String> = ["Microsoft Corporation".to_string()].into();
        assert!(signer_matches("CN=Microsoft Windows Publisher, O=Microsoft Corporation", &ms));
        let tg: BTreeSet<String> = ["Telegram FZ-LLC".to_string()].into();
        assert!(!signer_matches("CN=Telegram FZ-LLC Fake, O=Evil Ltd", &tg));
    }

    #[test]
    fn checker_requires_valid_signature_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("Telegram.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut checker = TrustChecker::new(
            parse_trusted("Telegram.exe=Telegram FZ-LLC"),
            Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Signature { status: "Valid".into(), subject: "CN=Telegram FZ-LLC, O=Telegram FZ-LLC".into() }
            }),
        );
        let none = BTreeSet::new();
        assert!(checker.is_trusted(exe.to_str().unwrap(), &none));
        assert!(checker.is_trusted(exe.to_str().unwrap(), &none));
        assert_eq!(calls.load(Ordering::SeqCst), 1); // закэшировано
        let stealer = dir.path().join("crack.exe");
        std::fs::write(&stealer, b"MZ").unwrap();
        assert!(!checker.is_trusted(stealer.to_str().unwrap(), &none));
        assert_eq!(calls.load(Ordering::SeqCst), 1); // имени нет в списке — подпись даже не читали
    }

    #[test]
    fn renamed_unsigned_exe_and_pinned_hash() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("Telegram.exe");
        std::fs::write(&fake, b"MZ").unwrap();
        let mut checker = TrustChecker::new(
            parse_trusted("Telegram.exe=Telegram FZ-LLC"),
            Box::new(|_| Signature { status: "NotSigned".into(), subject: String::new() }),
        );
        assert!(!checker.is_trusted(fake.to_str().unwrap(), &BTreeSet::new()));

        let tool = dir.path().join("backup.exe");
        std::fs::write(&tool, b"MZ backup").unwrap();
        let path = tool.to_str().unwrap();
        assert!(!checker.is_trusted(path, &BTreeSet::new()));
        let pinned: BTreeSet<String> = [sha256_file(path).unwrap()].into();
        checker.invalidate();
        assert!(checker.is_trusted(path, &pinned));
    }
}
