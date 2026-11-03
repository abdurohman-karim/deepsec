"""Инцидент — общий формат для агента (Windows) и сервера с ботом. Код совместим с Python 3.10."""
from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    CRITICAL = 3


class Kind(str, Enum):
    TDATA_ACCESS = "tdata_access"
    DECOY_ACCESS = "decoy_access"
    REMOTE_LOGON = "remote_logon"
    LOCAL_LOGON = "local_logon"
    FAILED_LOGONS = "failed_logons"
    LOG_CLEARED = "log_cleared"
    AUDIT_DISABLED = "audit_disabled"
    REMOTE_TOOL = "remote_tool"
    SELFTEST = "selftest"
    TOTP_BRUTEFORCE = "totp_bruteforce"
    NEW_LOGIN = "new_login"
    GUARD = "guard"
    AGENT_OFFLINE = "agent_offline"


@dataclass
class Incident:
    kind: Kind
    severity: Severity
    title: str
    details: dict[str, str] = field(default_factory=dict)
    pid: int | None = None
    process_path: str | None = None
    files: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    # True — инцидент требует автоматической реакции (kill / firewall / завершение сеансов), если защита «взведена».
    respond: bool = False
    session: int | None = None  # hash сеанса Telegram, если инцидент про вход в аккаунт
    host: str = ""  # компьютер, с которого пришёл инцидент; пусто — сам сервер
    id: str = field(default_factory=lambda: secrets.token_hex(3))
    time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def actions_include(self, label: str) -> bool:
        return any(a.startswith(label) for a in self.actions)

    def to_json(self) -> dict:
        data = asdict(self)
        data["time"] = self.time.isoformat()
        data["kind"] = self.kind.value
        data["severity"] = self.severity.name
        return data

    @classmethod
    def from_json(cls, data: dict) -> Incident:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**{
            **known,
            "kind": Kind(data["kind"]),
            "severity": Severity[data["severity"]],
            "time": datetime.fromisoformat(data["time"]),
        })
