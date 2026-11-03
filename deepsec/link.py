"""Связь агента с сервером: постоянный WebSocket, переподключение, доставка инцидентов с подтверждением."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

from .config import Config
from .incidents import Incident
from .protocol import AUTH_HEADER, HEARTBEAT, NAME_HEADER, normalize_fingerprint
from .state import Outbox

log = logging.getLogger(__name__)

# (action, args) -> (ok, текст для владельца, данные)
CommandHandler = Callable[[str, dict], Awaitable[tuple[bool, str, Any]]]


class Link:
    def __init__(self, cfg: Config, outbox: Outbox, on_command: CommandHandler, status: Callable[[], dict]):
        self._cfg = cfg
        self._outbox = outbox
        self._on_command = on_command
        self._status = status
        self._wake = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.connected = False
        if cfg.server_url.startswith("wss://"):
            self._ssl: Any = aiohttp.Fingerprint(bytes.fromhex(normalize_fingerprint(cfg.server_fingerprint)))
        else:
            self._ssl = True  # ws:// — только для тестов на localhost (TLS не используется)

    def send_incident(self, inc: Incident, armed: bool) -> None:
        self._outbox.add(inc.id, {"type": "incident", "incident": inc.to_json(), "armed": armed})
        self._wake.set()

    def push_status(self) -> None:
        self._wake.set()

    async def run(self) -> None:
        delay = 1
        headers = {AUTH_HEADER: f"Bearer {self._cfg.agent_token}", NAME_HEADER: self._cfg.agent_name}
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(self._cfg.server_url, headers=headers, ssl=self._ssl,
                                                  heartbeat=HEARTBEAT) as ws:
                        log.info("Подключён к серверу %s", self._cfg.server_url)
                        delay = 1
                        await self._session(ws)
            except aiohttp.ServerFingerprintMismatch:
                log.error("Отпечаток сертификата сервера не совпал — возможна подмена сервера!")
            except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
                log.warning("Нет связи с сервером: %s", e)
            finally:
                self.connected = False
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)

    async def _session(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        self.connected = True
        await ws.send_json({"type": "hello", "status": self._status()})
        sender = asyncio.ensure_future(self._sender(ws))
        try:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                data = msg.json()
                if data.get("type") == "ack":
                    self._outbox.ack(str(data.get("id")))
                elif data.get("type") == "command":
                    task = asyncio.ensure_future(self._execute(ws, data))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
        finally:
            sender.cancel()

    async def _sender(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        sent: set[str] = set()
        while True:
            for key, message in self._outbox.items():
                if key not in sent:
                    await ws.send_json(message)
                    sent.add(key)
            try:
                await asyncio.wait_for(self._wake.wait(), HEARTBEAT)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            await ws.send_json({"type": "status", "status": self._status()})

    async def _execute(self, ws: aiohttp.ClientWebSocketResponse, data: dict) -> None:
        try:
            ok, text, payload = await self._on_command(str(data.get("action")), dict(data.get("args") or {}))
        except Exception as e:
            log.exception("Команда %s упала", data.get("action"))
            ok, text, payload = False, f"ошибка — {e}", None
        try:
            await ws.send_json({"type": "result", "id": data.get("id"), "ok": ok, "text": text,
                                "data": payload, "status": self._status()})
        except (aiohttp.ClientError, ConnectionError, RuntimeError):
            log.warning("Не удалось отправить результат команды — связь пропала")
