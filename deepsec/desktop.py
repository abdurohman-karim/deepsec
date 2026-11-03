"""Экран и программы пользователя — по запросу владельца из бота.

Агент работает от SYSTEM в служебном сеансе 0, откуда экран и окна пользователя не видны. Поэтому на время
запроса он запускает себя же (`DeepSecAgent.exe desktop screenshot|apps`) в сеансе того, кто сидит за
компьютером, с правами этого пользователя. Помощник печатает JSON в канал и завершается — постоянно
в сеансе пользователя ничего не работает.
"""
from __future__ import annotations

import base64
import ctypes
import io
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import psutil

from .config import PROJECT_DIR

WHAT = ("screenshot", "apps")
HELPER_TIMEOUT = 25  # сек: сервер ждёт ответа агента 40 с
MAX_SIDE = 2560  # Telegram всё равно ужмёт фото до 2560 px по длинной стороне
JPEG_QUALITY = 70
MAX_TITLE = 100
MAX_BACKGROUND = 40
SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class DesktopError(RuntimeError):
    pass


# ---------- агент (SYSTEM): запуск помощника в сеансе пользователя ----------

def helper_command(*args: str) -> tuple[list[str], str]:
    """(команда, рабочая папка) помощника — из установщика или из исходников."""
    if getattr(sys, "frozen", False):  # собрано PyInstaller
        return [sys.executable, *args], str(Path(sys.executable).parent)
    python = Path(sys.executable)
    if python.name.lower() == "pythonw.exe":
        python = python.with_name("python.exe")  # у pythonw нет stdout — не получим ответ
    return [str(python), "-m", "deepsec", *args], str(PROJECT_DIR)


def helper_args(cmdline: list[str]) -> list[str]:
    """Аргументы помощника из командной строки процесса: всё после DeepSecAgent.exe или «-m deepsec»."""
    for i, part in enumerate(cmdline):
        if i == 0 and part.lower().endswith("deepsecagent.exe"):
            return cmdline[1:]
        if part == "deepsec" and i and cmdline[i - 1] == "-m":
            return cmdline[i + 1:]
    return []


def run_in_user_session(what: str, timeout: float = HELPER_TIMEOUT) -> dict[str, Any]:
    session = _require_session()
    cmd, cwd = helper_command("desktop", what)
    if _same_session(session):
        # Агент запущен не от SYSTEM, а в том же сеансе (отладка из исходников) — токен не нужен.
        try:
            done = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        except subprocess.TimeoutExpired:
            raise DesktopError("помощник не ответил вовремя") from None
        return parse_output(done.stdout)
    return parse_output(_run_as_user(session, cmd, cwd, timeout))


def start_in_user_session(*args: str) -> int:
    """Запускает помощника в сеансе пользователя и не ждёт его (питомец живёт, пока его не уберут). Возвращает PID."""
    session = _require_session()
    cmd, cwd = helper_command(*args)
    if _same_session(session):
        return subprocess.Popen(cmd, cwd=cwd, creationflags=NO_WINDOW).pid
    process, pid = _create_as_user(session, cmd, cwd)
    process.Close()
    return pid


def stop_helpers(command: str) -> int:
    """Завершает запущенных помощников этой команды (например, всех питомцев). Возвращает, сколько было."""
    found = [p for p in psutil.process_iter(["cmdline"]) if helper_args(p.info["cmdline"] or [])[:1] == [command]]
    for p in found:
        try:
            p.kill()
        except psutil.Error:
            pass
    return len(found)


def _require_session() -> int:
    session = _active_session()
    if session is None:
        raise DesktopError("за компьютером никто не работает: открыт экран входа или пользователь отключён")
    return session


def _same_session(session: int) -> bool:
    import win32ts

    return win32ts.ProcessIdToSessionId(os.getpid()) == session


def _active_session() -> int | None:
    """Сеанс, в котором сейчас работают: сначала консоль (монитор компьютера), иначе активный RDP."""
    import win32ts

    active = [s["SessionId"] for s in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE)
              if s["State"] == win32ts.WTSActive and s["SessionId"] != 0]
    console = win32ts.WTSGetActiveConsoleSessionId()
    if console in active:
        return console
    return active[0] if active else None


def _create_as_user(session: int, cmd: list[str], cwd: str, stdout: Any = None) -> tuple[Any, int]:
    """Процесс с правами пользователя сеанса, на его рабочем столе. Возвращает (дескриптор, PID)."""
    import pywintypes
    import win32process
    import win32profile
    import win32ts

    try:
        token = win32ts.WTSQueryUserToken(session)
    except pywintypes.error as e:
        raise DesktopError(f"нет доступа к сеансу пользователя ({e.strerror}) — агент должен работать от SYSTEM") from e
    startup = win32process.STARTUPINFO()
    startup.lpDesktop = "winsta0\\default"
    if stdout is not None:
        startup.dwFlags = win32process.STARTF_USESTDHANDLES
        startup.hStdOutput = stdout
    try:
        env = win32profile.CreateEnvironmentBlock(token, False)
        process, thread, pid, _ = win32process.CreateProcessAsUser(
            token, None, subprocess.list2cmdline(cmd), None, None, stdout is not None,
            win32process.CREATE_NO_WINDOW | win32process.CREATE_UNICODE_ENVIRONMENT, env, cwd, startup)
    except pywintypes.error as e:
        raise DesktopError(f"не удалось запустить помощника: {e.strerror}") from e
    finally:
        token.Close()
    thread.Close()
    return process, pid


def _run_as_user(session: int, cmd: list[str], cwd: str, timeout: float) -> bytes:
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32file
    import win32pipe
    import win32process

    attrs = pywintypes.SECURITY_ATTRIBUTES()
    attrs.bInheritHandle = True
    read, write = win32pipe.CreatePipe(attrs, 0)
    win32api.SetHandleInformation(read, win32con.HANDLE_FLAG_INHERIT, 0)  # помощнику — только запись
    try:
        process, _ = _create_as_user(session, cmd, cwd, stdout=write)
    except DesktopError:
        read.Close()
        raise
    finally:
        write.Close()  # иначе чтение не увидит конца, когда помощник завершится

    timed_out = threading.Event()

    def kill() -> None:
        timed_out.set()
        win32process.TerminateProcess(process, 1)

    killer = threading.Timer(timeout, kill)
    killer.start()
    chunks = []
    try:
        while True:
            try:
                _, chunk = win32file.ReadFile(read, 65536)
            except pywintypes.error:  # ERROR_BROKEN_PIPE — помощник закончил
                break
            chunks.append(chunk)
        win32event.WaitForSingleObject(process, 5000)
    finally:
        killer.cancel()
        read.Close()
        process.Close()
    if timed_out.is_set():
        raise DesktopError("помощник не ответил вовремя")
    return b"".join(chunks)


def parse_output(raw: bytes) -> dict[str, Any]:
    lines = raw.decode("utf-8", "replace").strip().splitlines()
    try:
        data = json.loads(lines[-1])
    except (IndexError, ValueError):
        raise DesktopError("помощник завершился без ответа") from None
    if not isinstance(data, dict):
        raise DesktopError("помощник ответил непонятно")
    return data


# ---------- помощник (сеанс пользователя) ----------

def helper_main(what: str) -> int:
    try:
        data = collect(what)
    except Exception as e:
        data = {"error": f"ошибка — {e}"}
    sys.stdout.write(json.dumps(data, ensure_ascii=True) + "\n")
    sys.stdout.flush()
    return 0


def collect(what: str) -> dict[str, Any]:
    import win32api
    import win32gui

    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # иначе на 125% снимок обрезан
    except (AttributeError, OSError):
        pass
    foreground = win32gui.GetForegroundWindow()
    data: dict[str, Any] = {
        "user": win32api.GetUserName(),
        "locked": _input_desktop() != "default",
        "idle": _idle_seconds(),
    }
    windows = _windows(foreground)
    data["active"] = next((w for w in windows if w["active"]), None)
    if what == "screenshot":
        if data["locked"]:
            data["error"] = "экран заблокирован — на нём только окно входа в Windows"
        else:
            data.update(_screenshot())
    else:
        data["windows"] = windows
        data["background"] = background_names(_session_processes(), {w["exe"].lower() for w in windows})
    return data


def _input_desktop() -> str:
    import pywintypes
    import win32con
    import win32service

    try:
        desktop = win32service.OpenInputDesktop(0, False, win32con.DESKTOP_READOBJECTS)
    except pywintypes.error:
        return "winlogon"  # экран блокировки: к нему у пользователя доступа нет
    try:
        return str(win32service.GetUserObjectInformation(desktop, win32con.UOI_NAME)).lower()
    finally:
        desktop.CloseDesktop()


def _idle_seconds() -> float:
    import win32api

    return ((win32api.GetTickCount() - win32api.GetLastInputInfo()) & 0xFFFFFFFF) / 1000


def _screenshot() -> dict[str, Any]:
    from PIL import ImageGrab

    image = ImageGrab.grab(all_screens=True)
    size = list(image.size)
    if not image.convert("L").getbbox():
        return {"error": "снимок получился чёрным — вероятно, открыт запрос UAC или защищённый экран"}
    image.thumbnail((MAX_SIDE, MAX_SIDE))
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, "JPEG", quality=JPEG_QUALITY, optimize=True)
    return {"jpeg": base64.b64encode(buffer.getvalue()).decode(), "size": size}


def _windows(foreground: int) -> list[dict[str, Any]]:
    """Окна, которые видны на панели задач: с заголовком, без владельца, не служебные и не скрытые DWM."""
    import win32con
    import win32gui
    import win32process

    found: list[dict[str, Any]] = []

    def visit(hwnd: int, _: Any) -> bool:
        if not win32gui.IsWindowVisible(hwnd) or win32gui.GetWindow(hwnd, win32con.GW_OWNER):
            return True
        if win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOOLWINDOW:
            return True
        title = win32gui.GetWindowText(hwnd).strip()
        if not title or win32gui.GetClassName(hwnd) == "Progman" or _cloaked(hwnd):
            return True
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        found.append({"title": title[:MAX_TITLE], "exe": _exe_name(pid), "pid": pid,
                      "minimized": bool(win32gui.IsIconic(hwnd)), "active": hwnd == foreground})
        return True

    win32gui.EnumWindows(visit, None)
    return found


def _cloaked(hwnd: int) -> bool:
    """Приложения Магазина держат невидимые («cloaked») окна — в списке они лишние."""
    value = ctypes.c_int(0)
    try:
        ctypes.windll.dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(value), ctypes.sizeof(value))
    except OSError:
        return False
    return bool(value.value)


def _exe_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return "?"


def _session_processes() -> Iterable[tuple[str, str]]:
    import pywintypes
    import win32ts

    own = {os.getpid(), os.getppid()}
    session = win32ts.ProcessIdToSessionId(os.getpid())
    for p in psutil.process_iter(["name", "exe"]):
        try:
            if p.pid in own or win32ts.ProcessIdToSessionId(p.pid) != session:
                continue
        except pywintypes.error:
            continue
        yield p.info["name"] or "", p.info["exe"] or ""


def background_names(processes: Iterable[tuple[str, str]], window_exes: set[str],
                     system_root: str = SYSTEM_ROOT) -> list[str]:
    """Программы пользователя без окон (трей, фоновые). Процессы Windows и уже показанные окнами — не нужны."""
    root = system_root.lower().rstrip("\\") + "\\"
    names: dict[str, str] = {}
    for name, exe in processes:
        if not name or not exe or exe.lower().startswith(root) or name.lower() in window_exes:
            continue
        names.setdefault(name.lower(), name)
    return sorted(names.values(), key=str.lower)[:MAX_BACKGROUND]
