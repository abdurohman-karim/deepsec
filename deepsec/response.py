"""Активная реакция: завершение процесса, блокировка в брандмауэре, карантин, блокировка сеансов, изоляция.

Все функции синхронные и Windows-only — агент вызывает их через asyncio.to_thread.
"""
from __future__ import annotations

import hashlib
import ntpath
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import psutil

from .detector import norm_path

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
RULE_PREFIX = "DeepSec-Block-"
ISOLATION_RULES = ("DeepSec-Isolation-Agent", "DeepSec-Isolation-DNS-UDP", "DeepSec-Isolation-DNS-TCP")
# Эти процессы нельзя убивать — получим синий экран или сломанную систему.
PROTECTED = frozenset({
    "system", "registry", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
})


class ResponseError(RuntimeError):
    pass


def is_protected_path(path: str | None) -> bool:
    return not path or ntpath.basename(path).lower() in PROTECTED


def is_protected(pid: int | None, path: str | None) -> bool:
    return pid is None or pid <= 4 or is_protected_path(path)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, encoding="oem", errors="replace", creationflags=NO_WINDOW)


def _netsh(*args: str) -> None:
    result = _run("netsh", "advfirewall", *args)
    if result.returncode != 0:
        raise ResponseError((result.stdout or result.stderr).strip() or f"netsh вернул {result.returncode}")


def kill_tree(pid: int, expected_path: str | None) -> str:
    try:
        proc = psutil.Process(pid)
        if expected_path and norm_path(proc.exe()) != norm_path(expected_path):
            return f"PID {pid} уже занят другим процессом — не трогаю"
        if is_protected(pid, proc.exe()):
            return f"{proc.name()} — системный процесс, завершать нельзя"
        procs = [*proc.children(recursive=True), proc]
    except psutil.NoSuchProcess:
        return f"процесс {pid} уже завершился"
    except psutil.AccessDenied:
        return f"нет доступа к процессу {pid}"

    for p in procs:
        try:
            p.kill()
        except psutil.Error:
            pass
    gone, alive = psutil.wait_procs(procs, timeout=3)
    result = f"завершено процессов: {len(gone)}"
    return result + (f", не удалось: {len(alive)}" if alive else "")


def block_rule_name(path: str) -> str:
    return RULE_PREFIX + hashlib.sha1(norm_path(path).encode()).hexdigest()[:10]


def block_program(path: str) -> str:
    """Запрещает exe любой сетевой трафик (даже если его запустят снова). Возвращает имя правила."""
    if is_protected_path(path):
        raise ResponseError(f"{ntpath.basename(path)} — системный процесс, блокировать нельзя")
    name = block_rule_name(path)
    for direction in ("out", "in"):
        _netsh("firewall", "add", "rule", f"name={name}", f"dir={direction}", "action=block",
               f"program={path}", "enable=yes")
    return name


def unblock(rule_name: str) -> None:
    _netsh("firewall", "delete", "rule", f"name={rule_name}")


def quarantine(path: str, data_dir: str) -> str:
    if is_protected_path(path):
        raise ResponseError(f"{ntpath.basename(path)} — системный файл, в карантин нельзя")
    target_dir = Path(data_dir) / "quarantine"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{datetime.now():%Y%m%d-%H%M%S}_{ntpath.basename(path)}.quarantine"
    try:
        shutil.move(path, target)
    except OSError as e:
        raise ResponseError(f"не удалось переместить (процесс ещё жив?): {e}") from e
    return str(target)


def lock_sessions() -> str:
    """Отключает все активные сеансы — консольный (экран блокировки) и RDP (выкидывает подключившегося)."""
    import ctypes
    from ctypes import wintypes

    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR), ("State", ctypes.c_int)]

    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    info = ctypes.POINTER(WTS_SESSION_INFOW)()
    count = wintypes.DWORD()
    if not wtsapi32.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(info), ctypes.byref(count)):
        raise ResponseError(f"WTSEnumerateSessions: WinError {ctypes.get_last_error()}")
    locked = []
    try:
        for i in range(count.value):
            session = info[i]
            if session.State == 0 and session.SessionId != 0:  # WTSActive, не служебная session 0
                if wtsapi32.WTSDisconnectSession(None, session.SessionId, False):
                    locked.append(session.pWinStationName or str(session.SessionId))
    finally:
        wtsapi32.WTSFreeMemory(info)

    if not locked:
        # Агент запущен не от SYSTEM и не смог отключить сеанс — блокируем хотя бы свой.
        if ctypes.windll.user32.LockWorkStation():
            return "рабочая станция заблокирована"
        raise ResponseError("нет активных сеансов или недостаточно прав")
    return "отключены сеансы: " + ", ".join(locked)


def isolate(agent_exe: str) -> None:
    """Режет весь сетевой трафик ПК, кроме самого агента (чтобы бот остался на связи) и DNS."""
    _netsh("set", "allprofiles", "state", "on")
    _netsh("firewall", "add", "rule", f"name={ISOLATION_RULES[0]}", "dir=out", "action=allow",
           f"program={agent_exe}", "enable=yes")
    _netsh("firewall", "add", "rule", f"name={ISOLATION_RULES[1]}", "dir=out", "action=allow",
           "protocol=UDP", "remoteport=53", "enable=yes")
    _netsh("firewall", "add", "rule", f"name={ISOLATION_RULES[2]}", "dir=out", "action=allow",
           "protocol=TCP", "remoteport=53", "enable=yes")
    _netsh("set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")


def unisolate() -> None:
    _netsh("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
    for name in ISOLATION_RULES:
        _run("netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}")
