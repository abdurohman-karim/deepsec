"""Обновление агента из GitHub Releases: найти новую версию, скачать установщик, сверить SHA-256, поставить тихо.

CI на каждую новую версию публикует релиз vX.Y.Z с DeepSecSetup-X.Y.Z.exe, а GitHub считает SHA-256
каждого файла релиза. Агент (SYSTEM) скачивает установщик в свою папку данных (писать туда может только
администратор — подменить файл до запуска нельзя), сверяет хэш и запускает установщик тихо, отдельной
задачей планировщика. Настройки (.env), состояние, ловушки и задача агента остаются как были.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REPO = "abdurohman-karim/deepsec"
TASK_NAME = "DeepSec Update"
REOPEN_FLAG = "reopen-window"  # обновлялись из окна — после перезапуска агент откроет его снова
ASSET_RE = re.compile(r"^DeepSecSetup-(\d+\.\d+\.\d+)\.exe$")
TIMEOUT = 30
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Отдельная задача от SYSTEM: установщик останавливает задачу агента вместе с её процессами, поэтому
# запускать его из самого агента нельзя — он погиб бы на середине.
_PS_RUN_INSTALLER = r"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute $env:DEEPSEC_INSTALLER -Argument $env:DEEPSEC_ARGS
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName $env:DEEPSEC_TASK -Action $action -Principal $principal -Settings $settings `
    -Force | Out-Null
Start-ScheduledTask -TaskName $env:DEEPSEC_TASK
"""


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class Release:
    version: str
    url: str
    sha256: str
    name: str


def parse_version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value)[:3])


def is_newer(candidate: str, current: str) -> bool:
    return parse_version(candidate) > parse_version(current)


def release_from_json(data: dict, repo: str = DEFAULT_REPO) -> Release | None:
    """Установщик из ответа GitHub API. Без SHA-256 от GitHub или с чужой ссылкой — не берём."""
    prefix = f"https://github.com/{repo}/releases/download/"
    for asset in data.get("assets") or []:
        match = ASSET_RE.match(asset.get("name") or "")
        digest = str(asset.get("digest") or "")
        url = str(asset.get("browser_download_url") or "")
        if match and digest.startswith("sha256:") and url.startswith(prefix):
            return Release(match[1], url, digest.removeprefix("sha256:").lower(), asset["name"])
    return None


def latest_release(repo: str = DEFAULT_REPO) -> Release | None:
    request = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "DeepSec-agent"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return release_from_json(json.load(response), repo)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # релизов ещё нет
        raise UpdateError(f"GitHub ответил {e.code}") from e
    except (OSError, ValueError) as e:  # нет сети, GitHub недоступен, 404 — релизов ещё нет, битый ответ
        raise UpdateError(f"GitHub не ответил: {e}") from e


def download(release: Release, folder: Path, progress: Callable[[int, int], None] | None = None) -> Path:
    """Скачать установщик и сверить SHA-256. progress(скачано, всего) — для полосы загрузки в окне."""
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / release.name
    digest = hashlib.sha256()
    request = urllib.request.Request(release.url, headers={"User-Agent": "DeepSec-agent"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response, target.open("wb") as f:
            total, done = int(response.headers.get("Content-Length") or 0), 0
            while chunk := response.read(256 * 1024):
                digest.update(chunk)
                f.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except OSError as e:
        target.unlink(missing_ok=True)
        raise UpdateError(f"не удалось скачать {release.name}: {e}") from e
    if digest.hexdigest() != release.sha256:
        target.unlink(missing_ok=True)
        raise UpdateError("SHA-256 скачанного установщика не совпал с опубликованным — файл удалён, ничего не ставлю")
    return target


def install(installer: Path, log_dir: Path) -> None:
    args = f'/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG="{log_dir / "install.log"}"'
    env = {**os.environ, "DEEPSEC_INSTALLER": str(installer), "DEEPSEC_ARGS": args, "DEEPSEC_TASK": TASK_NAME}
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-Command", _PS_RUN_INSTALLER], capture_output=True, text=True, encoding="oem",
                            errors="replace", env=env, creationflags=NO_WINDOW)
    if result.returncode != 0:
        raise UpdateError(f"не удалось запустить установщик: {(result.stdout + result.stderr).strip()}")


def can_update() -> bool:
    """Обновлять установщиком можно только агента из установщика, не запущенного из исходников."""
    return bool(getattr(sys, "frozen", False))


def update(current: str, data_dir: str, repo: str = DEFAULT_REPO) -> str:
    """Проверить, скачать, сверить и запустить установку. Возвращает текст для владельца."""
    if not can_update():
        raise UpdateError("агент запущен из исходников — обновляйте его через git pull")
    release = latest_release(repo)
    if release is None:
        raise UpdateError("в релизах GitHub нет установщика с контрольной суммой")
    if not is_newer(release.version, current):
        return f"уже последняя версия ({current})"
    folder = Path(data_dir) / "updates"
    installer = download(release, folder)
    install(installer, folder)
    return f"{current} → {release.version}: установщик скачан, SHA-256 совпал, ставлю. Агент перезапустится примерно через минуту"


class Updater:
    """Обновление в фоне: проверка → загрузка с прогрессом → установка по команде.

    Состояние видят окно DeepSec (через локальный канал агента) и бот (в статусе агента). Окно ставит
    обновление само, только когда пользователь нажал «Перезапустить», бот — сразу после загрузки.
    """

    BUSY = frozenset({"checking", "downloading", "installing"})

    def __init__(self, current: str, data_dir: str, repo: str = DEFAULT_REPO,
                 on_change: Callable[[], None] | None = None):
        self.current, self.repo = current, repo
        self.folder = Path(data_dir) / "updates"
        self.on_change = on_change or (lambda: None)
        # idle | checking | latest | available | downloading | ready | installing | error
        self.state = "idle"
        self.release: Release | None = None
        self.done = self.total = 0
        self.error = ""
        self.installer: Path | None = None
        self._task: asyncio.Task | None = None

    @property
    def available(self) -> str:
        """Новая версия, если она есть в релизах."""
        return self.release.version if self.release and is_newer(self.release.version, self.current) else ""

    def snapshot(self) -> dict:
        return {"version": self.current, "state": self.state, "latest": self.release.version if self.release else "",
                "available": self.available, "done": self.done, "total": self.total, "error": self.error}

    def _set(self, state: str, error: str = "") -> None:
        self.state, self.error = state, error
        self.on_change()

    async def check(self) -> None:
        if self.state in self.BUSY or self.state == "ready":
            return
        self._set("checking")
        try:
            self.release = await asyncio.to_thread(latest_release, self.repo)
        except Exception as e:  # что бы ни случилось с GitHub, защита работать не перестаёт
            self._set("error", str(e))
            return
        self._set("available" if self.available else "latest")

    def start(self, install_after: bool = False) -> bool:
        """Начать загрузку в фоне. False — уже идёт, уже скачано или обновлять нечего."""
        if not can_update():
            self._set("error", "агент запущен из исходников — обновляйте его через git pull")
            return False
        if self.state in self.BUSY or not self.available:
            return False
        if self.state == "ready":
            if install_after:
                self._task = asyncio.ensure_future(self._install_quietly())
            return install_after
        self._task = asyncio.ensure_future(self._download(install_after))
        return True

    async def _download(self, install_after: bool) -> None:
        self.done, self.total = 0, 0
        self._set("downloading")
        try:
            self.installer = await asyncio.to_thread(download, self.release, self.folder, self._progress)
        except Exception as e:
            self._set("error", str(e))
            return
        self._set("ready")
        if install_after:
            await self._install_quietly()

    def _progress(self, done: int, total: int) -> None:
        self.done, self.total = done, total  # окно само опрашивает — без лишних сообщений серверу

    async def _install_quietly(self) -> None:
        try:
            await self.install()
        except UpdateError:
            pass  # ошибка уже в self.error — её увидят бот и окно

    async def install(self, reopen_window: bool = False) -> None:
        """Запустить установку скачанного. Установщик остановит агента и запустит уже новую версию."""
        if self.state != "ready" or self.installer is None:
            raise UpdateError("сначала скачайте обновление")
        self._set("installing")
        if reopen_window:
            (self.folder / REOPEN_FLAG).write_text(self.current, "utf-8")
        try:
            await asyncio.to_thread(install, self.installer, self.folder)
        except Exception as e:
            self._set("error", str(e))
            raise UpdateError(str(e)) from e


def take_reopen_flag(data_dir: str) -> str | None:
    """После обновления из окна: с какой версии обновились (окно откроется снова и скажет об этом)."""
    flag = Path(data_dir) / "updates" / REOPEN_FLAG
    try:
        previous = flag.read_text("utf-8").strip()
        flag.unlink()
        return previous
    except OSError:
        return None


def cleanup(data_dir: str) -> None:
    """После обновления: убрать разовую задачу и старые установщики. Агент зовёт это через пару минут после
    старта — к этому времени установщик, который его перезапустил, уже точно завершился."""
    subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], capture_output=True, creationflags=NO_WINDOW)
    for old in (Path(data_dir) / "updates").glob("DeepSecSetup-*.exe"):
        try:
            old.unlink()
        except OSError:
            pass  # ещё занят установщиком — удалим в следующий раз
