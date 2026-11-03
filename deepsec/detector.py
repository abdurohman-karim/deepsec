"""Правила: превращают события журнала безопасности Windows в инциденты."""
from __future__ import annotations

import ntpath
import time
from collections import deque
from collections.abc import Awaitable, Callable

from .config import Config
from .incidents import Incident, Kind, Severity
from .winevent import WinEvent

FILE_SYSTEM_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"
LOGON_GUID = "{0CCE9215-69AE-11D9-BED3-505054503030}"
AUDIT_POLICY_CHANGE_GUID = "{0CCE922F-69AE-11D9-BED3-505054503030}"
# Коды в поле AuditPolicyChanges события 4719: %%8448 «успех удалён», %%8450 «сбой удалён».
AUDIT_REMOVED_CODES = ("%%8448", "%%8450")

LOGON_TYPES = {
    "2": "вход за компьютером",
    "3": "сетевой вход",
    "7": "разблокировка",
    "8": "сетевой вход (открытый пароль)",
    "10": "RDP",
    "11": "вход по кэшу",
}
SERVICE_DOMAINS = {"window manager", "font driver host", "nt authority"}
LOCAL_IPS = {"", "-", "127.0.0.1", "::1"}
LOGON_DEDUP_SECONDS = 15


def norm_path(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path)) if path else ""


def is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("\\") + "\\")


def parse_pid(value: str) -> int | None:
    try:
        return int(value, 0)  # в журнале PID записан как 0x1a2c
    except ValueError:
        return None


def account(ev: WinEvent, prefix: str) -> str:
    user, domain = ev.get(f"{prefix}UserName"), ev.get(f"{prefix}DomainName")
    return f"{domain}\\{user}" if domain and domain != "-" else user


class Detector:
    def __init__(
        self,
        cfg: Config,
        is_trusted: Callable[[str], Awaitable[bool]],
        self_pid: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._cfg = cfg
        self._is_trusted = is_trusted
        self._self_pid = self_pid
        self._clock = clock
        self._tdata = [norm_path(p) for p in cfg.tdata_dirs]
        self._decoys = [norm_path(p) for p in cfg.decoy_dirs]
        self._canary = norm_path(cfg.canary_file)
        self._failed: deque[tuple[float, WinEvent]] = deque()
        self._recent_logons: dict[tuple[str, str], float] = {}
        # Когда последний раз видели чтение canary-файла самим агентом (самопроверка аудита).
        self.selftest_seen = float("-inf")

    async def process(self, ev: WinEvent) -> Incident | None:
        match ev.event_id:
            case 4663:
                return await self._file_access(ev)
            case 4624:
                return self._logon(ev)
            case 4625:
                return self._failed_logon(ev)
            case 4719:
                return self._audit_policy(ev)
            case 1102:
                return Incident(
                    Kind.LOG_CLEARED, Severity.CRITICAL, "Журнал безопасности Windows очищен",
                    details={"кто": account(ev, "Subject")},
                )
        return None

    async def _file_access(self, ev: WinEvent) -> Incident | None:
        raw_path = ev.get("ObjectName")
        path = norm_path(raw_path)
        pid = parse_pid(ev.get("ProcessId"))

        if path == self._canary:
            if pid == self._self_pid:
                self.selftest_seen = self._clock()
            return None

        if any(is_under(path, d) for d in self._decoys):
            kind, title = Kind.DECOY_ACCESS, "Кто-то читает файлы-ловушку tdata"
        elif any(is_under(path, d) for d in self._tdata):
            kind, title = Kind.TDATA_ACCESS, "Чужой процесс читает сессию Telegram"
        else:
            return None

        process = ev.get("ProcessName")
        if pid == self._self_pid or (process and await self._is_trusted(process)):
            return None
        if pid == 4 or not process:
            title += " (ядро/SMB — возможно, доступ по сети)"

        return Incident(
            kind, Severity.CRITICAL, title,
            pid=pid, process_path=process or None, files=[raw_path],
            details={"пользователь": account(ev, "Subject")},
            respond=True,
        )

    def _logon(self, ev: WinEvent) -> Incident | None:
        logon_type = ev.get("LogonType")
        user, domain = ev.get("TargetUserName"), ev.get("TargetDomainName")
        if (
            not user
            or user.endswith("$")
            or domain.lower() in SERVICE_DOMAINS
            or user.upper().startswith(("DWM-", "UMFD-"))
        ):
            return None

        ip = ev.get("IpAddress")
        if logon_type == "10":
            kind, severity, title = Kind.REMOTE_LOGON, Severity.CRITICAL, "RDP-подключение к компьютеру"
        elif logon_type in ("2", "7", "11"):
            if not self._cfg.alert_local_logons:
                return None
            kind, severity, title = Kind.LOCAL_LOGON, Severity.INFO, "Вход в Windows"
        elif logon_type in ("3", "8"):
            if not self._cfg.alert_network_logons or ip in LOCAL_IPS:
                return None
            kind, severity, title = Kind.REMOTE_LOGON, Severity.WARNING, "Сетевой вход в компьютер"
        else:
            return None

        # Один вход даёт пару событий (обычный и повышенный токен) — склеиваем.
        who = account(ev, "Target")
        key, now = (logon_type, who.lower()), self._clock()
        if now - self._recent_logons.get(key, float("-inf")) < LOGON_DEDUP_SECONDS:
            return None
        self._recent_logons[key] = now

        details = {"учётка": who, "тип": LOGON_TYPES.get(logon_type, logon_type)}
        if ip not in LOCAL_IPS:
            details["IP"] = ip
        if (station := ev.get("WorkstationName")) and station != "-":
            details["компьютер"] = station
        return Incident(kind, severity, title, details=details)

    def _failed_logon(self, ev: WinEvent) -> Incident | None:
        now = self._clock()
        self._failed.append((now, ev))
        while self._failed and now - self._failed[0][0] > self._cfg.failed_logon_window:
            self._failed.popleft()
        if len(self._failed) < self._cfg.failed_logon_threshold:
            return None

        attempts = [e for _, e in self._failed]
        self._failed.clear()
        ips = sorted({e.get("IpAddress") for e in attempts} - LOCAL_IPS)
        return Incident(
            Kind.FAILED_LOGONS,
            Severity.CRITICAL if ips else Severity.WARNING,
            f"Неудачные попытки входа: {len(attempts)}",
            details={
                "учётки": ", ".join(sorted({account(e, "Target") for e in attempts})),
                "IP": ", ".join(ips) or "локально",
                "тип": ", ".join(sorted({LOGON_TYPES.get(e.get("LogonType"), e.get("LogonType")) for e in attempts})),
            },
        )

    def _audit_policy(self, ev: WinEvent) -> Incident | None:
        guid = ev.get("SubcategoryGuid").upper()
        changes = ev.get("AuditPolicyChanges")
        if guid not in (FILE_SYSTEM_GUID, LOGON_GUID) or not any(c in changes for c in AUDIT_REMOVED_CODES):
            return None
        return Incident(
            Kind.AUDIT_DISABLED, Severity.CRITICAL, "Кто-то отключил аудит, на котором держится защита",
            details={"кто": account(ev, "Subject"), "подкатегория": guid},
        )
