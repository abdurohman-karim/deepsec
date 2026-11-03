"""Настройки Windows-агента (C:\\ProgramData\\DeepSec\\.env)."""
from __future__ import annotations

import ntpath
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = ntpath.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "DeepSec")

# Каким exe и с какой цифровой подписью (O= или CN= сертификата) разрешено читать tdata.
DEFAULT_TRUSTED = (
    "Telegram.exe=Telegram FZ-LLC|Telegram Messenger LLP;"
    "Updater.exe=Telegram FZ-LLC|Telegram Messenger LLP;"
    "MsMpEng.exe=Microsoft Corporation;"
    "MpDefenderCoreService.exe=Microsoft Corporation"
)


class ConfigError(RuntimeError):
    pass


def split_list(value: str | None) -> tuple[str, ...]:
    return tuple(p.strip() for p in (value or "").split(";") if p.strip())


def parse_flag(value: str | None, default: bool) -> bool:
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_trusted(spec: str) -> dict[str, frozenset[str]]:
    """'Telegram.exe=Org A|Org B;MsMpEng.exe=Microsoft Corporation' -> {'telegram.exe': {...}}"""
    result: dict[str, frozenset[str]] = {}
    for item in split_list(spec):
        name, _, signers = item.partition("=")
        result[name.strip().lower()] = frozenset(s.strip() for s in signers.split("|") if s.strip())
    return result


@dataclass(frozen=True)
class Config:
    server_url: str  # wss://IP:8443/agent
    server_fingerprint: str  # SHA-256 сертификата сервера (закреплён — подменить сервер нельзя)
    agent_token: str
    tdata_dirs: tuple[str, ...]
    agent_name: str = field(default_factory=platform.node)
    decoy_dirs: tuple[str, ...] = ()
    trusted: dict[str, frozenset[str]] = field(default_factory=lambda: parse_trusted(DEFAULT_TRUSTED))
    data_dir: str = DEFAULT_DATA_DIR
    auto_kill: bool = True
    auto_firewall: bool = True
    auto_lock: bool = False
    alert_local_logons: bool = True
    alert_network_logons: bool = False
    failed_logon_threshold: int = 3
    failed_logon_window: int = 300
    selftest_interval: int = 600
    process_poll_interval: float = 3.0

    @property
    def canary_file(self) -> str:
        return ntpath.join(self.data_dir, "canary", "selftest.bin")

    @classmethod
    def load(cls, env_file: str | os.PathLike | None = None) -> Config:
        candidates = [Path(env_file)] if env_file else [Path(DEFAULT_DATA_DIR) / ".env", PROJECT_DIR / ".env"]
        path = next((p for p in candidates if p.is_file()), None)
        if path is None:
            raise ConfigError("Не найден .env — сначала запустите `python -m deepsec setup` от администратора")
        return cls.from_mapping({k: v for k, v in dotenv_values(path).items() if v is not None})

    @classmethod
    def from_mapping(cls, env: dict[str, str]) -> Config:
        missing = [k for k in ("SERVER_URL", "AGENT_TOKEN", "TDATA_DIRS") if not env.get(k)]
        if env.get("SERVER_URL", "").startswith("wss://") and not env.get("SERVER_FINGERPRINT"):
            missing.append("SERVER_FINGERPRINT")
        if missing:
            raise ConfigError(f"В .env не заданы: {', '.join(missing)}")
        return cls(
            server_url=env["SERVER_URL"],
            server_fingerprint=env.get("SERVER_FINGERPRINT") or "",
            agent_token=env["AGENT_TOKEN"],
            agent_name=env.get("AGENT_NAME") or platform.node(),
            tdata_dirs=split_list(env["TDATA_DIRS"]),
            decoy_dirs=split_list(env.get("DECOY_DIRS")),
            trusted=parse_trusted(env.get("TRUSTED_PROCESSES") or DEFAULT_TRUSTED),
            data_dir=env.get("DATA_DIR") or DEFAULT_DATA_DIR,
            auto_kill=parse_flag(env.get("AUTO_KILL"), True),
            auto_firewall=parse_flag(env.get("AUTO_FIREWALL"), True),
            auto_lock=parse_flag(env.get("AUTO_LOCK"), False),
            alert_local_logons=parse_flag(env.get("ALERT_LOCAL_LOGONS"), True),
            alert_network_logons=parse_flag(env.get("ALERT_NETWORK_LOGONS"), False),
            failed_logon_threshold=int(env.get("FAILED_LOGON_THRESHOLD") or 3),
            failed_logon_window=int(env.get("FAILED_LOGON_WINDOW") or 300),
            selftest_interval=int(env.get("SELFTEST_INTERVAL") or 600),
            process_poll_interval=float(env.get("PROCESS_POLL_INTERVAL") or 3.0),
        )
