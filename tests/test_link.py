"""Сквозной тест: настоящий WebSocket между Link (агент) и Hub (сервер) на localhost."""
from __future__ import annotations

import asyncio
import dataclasses

from aiohttp import web

from deepsec.incidents import Incident, Kind, Severity
from deepsec.link import Link
from deepsec.server.hub import Hub
from deepsec.state import Outbox


class Events:
    def __init__(self) -> None:
        self.incidents: list[tuple[str, Incident, bool]] = []
        self.online = asyncio.Event()
        self.bad_auth: list[str] = []

    async def on_incident(self, agent, inc, armed):
        self.incidents.append((agent.name, inc, armed))

    async def on_online(self, agent, first_time):
        self.online.set()

    async def on_offline(self, agent):
        pass

    async def on_bad_auth(self, remote):
        self.bad_auth.append(remote)


async def start_hub(token: str):
    events = Events()
    hub = Hub(token, events)
    runner = web.AppRunner(hub.app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return hub, events, runner, f"ws://127.0.0.1:{port}/agent"


def test_incident_delivery_and_command_roundtrip(cfg, tmp_path):
    async def scenario():
        hub, events, runner, url = await start_hub("secret-token")
        outbox = Outbox(tmp_path / "outbox.json")
        commands = []

        async def on_command(action, args):
            commands.append((action, args))
            return True, "экран заблокирован", None

        link = Link(dataclasses.replace(cfg, server_url=url), outbox, on_command, lambda: {"armed": True})
        # Инцидент случился, пока сети не было — должен дойти после подключения.
        inc = Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "кража", pid=5, respond=True)
        link.send_incident(inc, armed=True)
        task = asyncio.ensure_future(link.run())
        try:
            await asyncio.wait_for(events.online.wait(), 5)
            for _ in range(50):
                if events.incidents and not outbox.items():
                    break
                await asyncio.sleep(0.05)
            result = await hub.command("HOME-PC", "lock")
            return events, outbox, commands, result, hub
        finally:
            task.cancel()
            await runner.cleanup()

    events, outbox, commands, result, hub = asyncio.run(scenario())
    (name, inc, armed), = events.incidents
    assert name == "HOME-PC" and inc.title == "кража" and armed
    assert outbox.items() == []  # сервер подтвердил получение
    assert commands == [("lock", {})]
    assert result.ok and result.text == "экран заблокирован"
    assert hub.agents["HOME-PC"].status == {"armed": True}


def test_wrong_token_is_rejected(cfg, tmp_path):
    async def scenario():
        hub, events, runner, url = await start_hub("secret-token")
        link = Link(dataclasses.replace(cfg, server_url=url, agent_token="wrong"), Outbox(None),
                    None, lambda: {})
        task = asyncio.ensure_future(link.run())
        await asyncio.sleep(0.3)
        task.cancel()
        await runner.cleanup()
        return hub, events

    hub, events = asyncio.run(scenario())
    assert events.bad_auth and not events.online.is_set() and hub.agents == {}


def test_command_to_offline_computer(cfg):
    hub = Hub("t", Events())
    result = asyncio.run(hub.command("NOPE", "lock"))
    assert not result.ok and "не на связи" in result.text
