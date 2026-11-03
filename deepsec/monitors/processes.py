"""Слежение за программами удалённого доступа — через них чаще всего «подключаются» к ПК."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

import psutil

REMOTE_TOOLS = {
    "anydesk.exe": "AnyDesk",
    "teamviewer.exe": "TeamViewer",
    "teamviewer_service.exe": "TeamViewer",
    "rustdesk.exe": "RustDesk",
    "rutserv.exe": "Remote Utilities / RMS",
    "rfusclient.exe": "Remote Utilities / RMS",
    "romserver.exe": "LiteManager",
    "aa_v3.exe": "Ammyy Admin",
    "aeroadmin.exe": "AeroAdmin",
    "rudesktop.exe": "RuDesktop",
    "winvnc.exe": "UltraVNC",
    "tvnserver.exe": "TightVNC",
    "vncserver.exe": "RealVNC",
    "screenconnect.clientservice.exe": "ScreenConnect",
    "supremo.exe": "Supremo",
    "supremoservice.exe": "Supremo",
    "dwagent.exe": "DWService",
    "meshagent.exe": "MeshCentral",
    "remoting_host.exe": "Chrome Remote Desktop",
    "parsecd.exe": "Parsec",
    "quickassist.exe": "Быстрая помощь Windows",
    "ngrok.exe": "ngrok (туннель наружу)",
}


@dataclass(frozen=True)
class FoundProcess:
    pid: int
    name: str
    exe: str
    tool: str


def _iter_processes() -> Iterable[tuple[int, str, str]]:
    for p in psutil.process_iter(["name", "exe"]):
        yield p.pid, p.info["name"] or "", p.info["exe"] or ""


class RemoteToolWatcher:
    def __init__(
        self,
        tools: dict[str, str] = REMOTE_TOOLS,
        iter_processes: Callable[[], Iterable[tuple[int, str, str]]] = _iter_processes,
    ):
        self._tools = tools
        self._iter = iter_processes
        self._seen: set[int] = set()

    def poll(self) -> list[FoundProcess]:
        """Возвращает процессы удалённого доступа, появившиеся с прошлого опроса (на первом — все запущенные)."""
        current = {
            pid: FoundProcess(pid, name, exe, self._tools[name.lower()])
            for pid, name, exe in self._iter()
            if name.lower() in self._tools
        }
        new = [p for pid, p in current.items() if pid not in self._seen]
        self._seen = set(current)
        return new
