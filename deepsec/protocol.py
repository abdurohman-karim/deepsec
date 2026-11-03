"""Протокол агент ↔ сервер: JSON-сообщения поверх WebSocket (TLS с закреплённым сертификатом сервера).

Агент → сервер:
    {"type": "hello" | "status", "status": {...}}
    {"type": "incident", "incident": {...}, "armed": bool}     — сервер отвечает {"type": "ack", "id": ...}
    {"type": "result", "id": ..., "ok": bool, "text": str, "data": ..., "status": {...}}
Сервер → агент:
    {"type": "command", "id": ..., "action": str, "args": {...}}
"""
from __future__ import annotations

AGENT_PATH = "/agent"
AUTH_HEADER = "Authorization"
NAME_HEADER = "X-DeepSec-Agent"
HEARTBEAT = 30  # сек: ping WebSocket и отправка статуса

# Команды, которые сервер может отдать агенту.
ACTIONS = frozenset({
    "status", "selftest", "arm", "disarm", "lock", "isolate", "unisolate",
    "kill", "block", "unblock", "quarantine", "trust", "screenshot", "apps", "pet", "pet_off", "close",
})
# Настроения пиксельного питомца на экране компьютера.
PET_MOODS = ("watch", "happy", "angry", "sleep")
PET_MAX_TEXT = 60
# Надписи по умолчанию (бот показывает их владельцу, агент — на экране).
PET_TEXTS = {
    "watch": "Katta og'a seni kuzatyabdi",
    "happy": "Zo'r o'ynayapsan!",
    "angry": "Ko'p o'ynama!",
    "sleep": "Katta og'a dam olyapti... zzz",
}


def normalize_fingerprint(value: str) -> str:
    """'AB:CD:…' или 'sha256 Fingerprint=AB:CD:…' -> 'abcd…'"""
    return value.rpartition("=")[2].replace(":", "").strip().lower()
