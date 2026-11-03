from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    CRITICAL = 3


class Kind(StrEnum):
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
    # True — инцидент требует автоматической реакции (kill / firewall), если агент «взведён».
    respond: bool = False
    id: str = field(default_factory=lambda: secrets.token_hex(3))
    time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_json(self) -> dict:
        data = asdict(self)
        data["time"] = self.time.isoformat()
        data["kind"] = str(self.kind)
        data["severity"] = self.severity.name
        return data

    @classmethod
    def from_json(cls, data: dict) -> Incident:
        return cls(**{
            **data,
            "kind": Kind(data["kind"]),
            "severity": Severity[data["severity"]],
            "time": datetime.fromisoformat(data["time"]),
        })
