"""Приём Windows-агентов: WebSocket-сервер, их статусы и отправка им команд."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from aiohttp import WSMsgType, web

from ..incidents import Incident
from ..protocol import AGENT_PATH, AUTH_HEADER, HEARTBEAT, NAME_HEADER

log = logging.getLogger(__name__)

COMMAND_TIMEOUT = 40  # сек: самопроверка на агенте идёт до 15 с
UNKNOWN_COMMAND = "неизвестная команда"  # так отвечает агент, которому команда не по версии
OLD_AGENT = "На компьютере старый агент — он этого не умеет. Поставьте новую версию установщика поверх."


def window_key(window: dict) -> str:
    """Ключ окна из списка «Что запущено» для кнопки: «PID-HWND» (двоеточие — разделитель callback_data)."""
    return f"{window.get('pid')}-{window.get('hwnd')}"


@dataclass
class AgentLink:
    name: str
    ws: web.WebSocketResponse | None = None
    status: dict = field(default_factory=dict)
    last_seen: float = 0.0
    offline_alerted: bool = False
    pending: dict[str, asyncio.Future] = field(default_factory=dict)

    @property
    def online(self) -> bool:
        return self.ws is not None and not self.ws.closed


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    text: str
    data: Any = None


class HubEvents(Protocol):
    async def on_incident(self, agent: AgentLink, inc: Incident, armed: bool) -> None: ...
    async def on_online(self, agent: AgentLink, first_time: bool) -> None: ...
    async def on_offline(self, agent: AgentLink) -> None: ...
    async def on_bad_auth(self, remote: str) -> None: ...


class Hub:
    def __init__(self, token: str, events: HubEvents, known: dict[str, float] | None = None):
        self._token = token
        self._events = events
        # Компьютеры, которые уже подключались: если такой не вернулся после перезапуска сервера — тоже тревога.
        self.agents: dict[str, AgentLink] = {name: AgentLink(name, last_seen=ts) for name, ts in (known or {}).items()}

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_get(AGENT_PATH, self._handle)
        return app

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        given = request.headers.get(AUTH_HEADER, "")
        if not hmac.compare_digest(given.encode(), f"Bearer {self._token}".encode()):
            await self._events.on_bad_auth(request.remote or "?")
            return web.Response(status=401)

        name = request.headers.get(NAME_HEADER, "").strip()[:40] or "PC"
        # 16 МБ: скриншот в JPEG обычно 200–500 КБ, но на нескольких 4K-мониторах бывает больше.
        ws = web.WebSocketResponse(heartbeat=HEARTBEAT, max_msg_size=16 << 20)
        await ws.prepare(request)
        first_time = name not in self.agents
        agent = self.agents.setdefault(name, AgentLink(name))
        if agent.online:
            await agent.ws.close()  # переподключился раньше, чем старое соединение умерло
        agent.ws, agent.last_seen = ws, time.time()
        await self._events.on_online(agent, first_time)
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    agent.last_seen = time.time()
                    await self._dispatch(agent, ws, json.loads(msg.data))
        except Exception:
            log.exception("Ошибка в соединении с агентом %s", name)
        finally:
            if agent.ws is ws:
                agent.ws = None
                for future in agent.pending.values():
                    if not future.done():
                        future.set_result({"ok": False, "text": "компьютер отключился"})
                agent.pending.clear()
                await self._events.on_offline(agent)
        return ws

    async def _dispatch(self, agent: AgentLink, ws: web.WebSocketResponse, data: dict) -> None:
        kind = data.get("type")
        if data.get("status"):
            agent.status = data["status"]
        if kind == "incident":
            inc = Incident.from_json(data["incident"])
            await self._events.on_incident(agent, inc, bool(data.get("armed")))
            await ws.send_json({"type": "ack", "id": inc.id})
        elif kind == "result":
            future = agent.pending.pop(str(data.get("id")), None)
            if future is not None and not future.done():
                future.set_result(data)

    async def command(self, name: str, action: str, **args: Any) -> CommandResult:
        agent = self.agents.get(name)
        if agent is None or not agent.online:
            return CommandResult(False, "компьютер не на связи")
        request_id = secrets.token_hex(4)
        future = asyncio.get_running_loop().create_future()
        agent.pending[request_id] = future
        try:
            await agent.ws.send_json({"type": "command", "id": request_id, "action": action, "args": args})
            data = await asyncio.wait_for(future, COMMAND_TIMEOUT)
        except asyncio.TimeoutError:
            return CommandResult(False, "компьютер не ответил")
        except ConnectionError:
            return CommandResult(False, "связь с компьютером оборвалась")
        finally:
            agent.pending.pop(request_id, None)
        return CommandResult(bool(data.get("ok")), str(data.get("text") or ""), data.get("data"))
