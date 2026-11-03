from __future__ import annotations

import asyncio
import dataclasses

import pytest

from deepsec import desktop, response
from deepsec.agent import Agent
from deepsec.server import screens
from deepsec.server.core import Server
from deepsec.server.hub import CommandResult

GAME = r"C:\Games\cs2\cs2.exe"
WINDOWS = [
    {"title": "Counter-Strike 2", "exe": "cs2.exe", "pid": 10, "hwnd": 1001, "active": True},
    {"title": "Downloads", "exe": "explorer.exe", "pid": 20, "hwnd": 2002},
]


def actions(markup) -> list[str]:
    return [b.callback_data.split(":")[1] for row in markup.inline_keyboard for b in row]


@pytest.fixture
def agent(cfg, tmp_path, monkeypatch):
    a = Agent(dataclasses.replace(cfg, data_dir=str(tmp_path)))
    a.killed = []
    monkeypatch.setattr(response, "kill_tree", lambda pid, path: a.killed.append((pid, path)) or "завершено процессов: 1")
    return a


def helper_reply(monkeypatch, reply: dict) -> list:
    calls = []

    def fake(what, *args, **kwargs):
        calls.append((what, *args))
        return dict(reply)

    monkeypatch.setattr(desktop, "run_in_user_session", fake)
    return calls


def test_window_closed_gently(agent, monkeypatch):
    calls = helper_reply(monkeypatch, {"exe": "cs2.exe", "path": GAME, "closed": True})
    assert asyncio.run(agent.execute("close", {"pid": 10, "hwnd": 1001})) == (True, "✖ Окно: cs2.exe закрыт", None)
    assert calls == [("close", "10", "1001")] and agent.killed == []


def test_hung_program_is_killed_after_waiting(agent, monkeypatch):
    helper_reply(monkeypatch, {"exe": "cs2.exe", "path": GAME, "closed": False})
    ok, text, _ = asyncio.run(agent.execute("close", {"pid": 10, "hwnd": 1001}))
    assert ok and "не закрылся сам" in text and "завершено процессов: 1" in text
    assert agent.killed == [(10, GAME)]


@pytest.mark.parametrize("path", [r"C:\Windows\explorer.exe", r"C:\Windows\System32\csrss.exe", ""])
def test_explorer_and_system_processes_are_never_killed(agent, monkeypatch, path):
    helper_reply(monkeypatch, {"exe": "x.exe", "path": path, "closed": False})
    ok, text, _ = asyncio.run(agent.execute("close", {"pid": 20, "hwnd": 2002}))
    assert ok and "принудительно не закрываю" in text and agent.killed == []


def test_stale_window_is_an_error(agent, monkeypatch):
    helper_reply(monkeypatch, {"error": "этого окна уже нет — обновите список"})
    ok, text, _ = asyncio.run(agent.execute("close", {"pid": 10, "hwnd": 1001}))
    assert not ok and "этого окна уже нет" in text and agent.killed == []


def test_bot_lists_close_buttons_and_confirms(server_cfg):
    server = Server(server_cfg)
    calls = []

    async def command(name, action, **args):
        calls.append((action, args))
        if action == "apps":
            return CommandResult(True, "", {"user": "me", "windows": WINDOWS, "background": []})
        return CommandResult(True, "✖ Окно: cs2.exe закрыт")

    server.hub.command = command

    async def scenario():
        text, markup = await screens.build(server, "apps", "HOME-PC")
        assert actions(markup) == ["close_q", "close_q", "shot", "apps", "pc"] and "✖ — закрыть окно" in text
        assert all(len(b.callback_data) <= 64 for row in markup.inline_keyboard for b in row)
        key = markup.inline_keyboard[0][0].callback_data.split(":")[3]
        assert key == "10-1001"

        text, markup = await screens.build(server, "close_q", "HOME-PC", extra=key)
        assert "cs2.exe" in text and "Counter-Strike 2" in text and actions(markup) == ["close", "apps"]
        text, markup = await screens.build(server, "close_q", "HOME-PC", extra="99-1")
        assert "устарел" in text and actions(markup) == ["apps"]

        assert (await server.perform("close", "HOME-PC", key)).startswith("✅")

    asyncio.run(scenario())
    assert ("close", {"pid": 10, "hwnd": 1001}) in calls
