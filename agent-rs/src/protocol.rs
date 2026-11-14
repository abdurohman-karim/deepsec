//! Протокол агент ↔ сервер — тот же, что у Python-агента (deepsec/protocol.py), сервер не меняется.
//!
//! Агент → сервер:
//!     {"type": "hello" | "status", "status": {...}}
//!     {"type": "incident", "incident": {...}, "armed": bool}   — сервер отвечает {"type": "ack", "id": ...}
//!     {"type": "result", "id": ..., "ok": bool, "text": str, "data": ..., "status": {...}}
//! Сервер → агент:
//!     {"type": "command", "id": ..., "action": str, "args": {...}}

pub const AGENT_PATH: &str = "/agent";
pub const AUTH_HEADER: &str = "Authorization";
pub const NAME_HEADER: &str = "X-DeepSec-Agent";
/// Секунды: ping WebSocket и отправка статуса.
pub const HEARTBEAT: u64 = 30;

/// Локальный канал агента для окна DeepSec (только 127.0.0.1).
pub const LOCAL_PORT: u16 = 47231;
pub const LOCAL_HEADER: &str = "X-DeepSec-Window";

/// Настроения пиксельного «Большого глаза» на экране компьютера.
pub const PET_MOODS: [&str; 4] = ["watch", "happy", "angry", "sleep"];
pub const PET_MAX_TEXT: usize = 60;

pub fn pet_text(mood: &str) -> &'static str {
    match mood {
        "happy" => "Zo'r o'ynayapsan!",
        "angry" => "Ko'p o'ynama!",
        "sleep" => "Katta og'a dam olyapti... zzz",
        _ => "Katta og'a seni kuzatyabdi",
    }
}

/// 'AB:CD:…' или 'sha256 Fingerprint=AB:CD:…' -> 'abcd…'
pub fn normalize_fingerprint(value: &str) -> String {
    let tail = value.rsplit('=').next().unwrap_or("");
    tail.replace(':', "").trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_normalized() {
        assert_eq!(normalize_fingerprint("sha256 Fingerprint=AB:CD:0F"), "abcd0f");
        assert_eq!(normalize_fingerprint(" ab:cd "), "abcd");
    }
}
