from __future__ import annotations

import asyncio
import dataclasses

import pytest

from deepsec import desktop
from deepsec.agent import Agent
from deepsec.pet import Pet, gaze
from deepsec.protocol import PET_MOODS
from deepsec.server import keyboards as kb
from deepsec.server import screens
from deepsec.server.core import Server
from deepsec.server.hub import AgentLink, CommandResult

ONLINE = type("WS", (), {"closed": False})()


def test_helper_args_from_command_line():
    assert desktop.helper_args([r"C:\Program Files\DeepSec\DeepSecAgent.exe", "pet", "watch"]) == ["pet", "watch"]
    assert desktop.helper_args(["python.exe", "-m", "deepsec", "pet", "sleep"]) == ["pet", "sleep"]
    assert desktop.helper_args([r"C:\Program Files\DeepSec\DeepSecAgent.exe", "run"]) == ["run"]
    assert desktop.helper_args(["notepad.exe", "pet.txt"]) == []


def test_eye_looks_toward_cursor_within_the_eye():
    left, up = gaze(-5000, -5000)
    assert -11 < left < -9 and -4 < up < -3
    assert gaze(0, 0) == (0, 0) and gaze(300, 0)[0] > 0


@pytest.mark.parametrize("mood", PET_MOODS)
def test_every_mood_draws_a_frame(mood):
    pytest.importorskip("PIL")
    pet = Pet(mood, "", scale=4)
    image = pet.frame()
    assert image.size == pet.size and image.getbbox() is not None
    assert Pet(mood, "x" * 200 + "\n", scale=4).text == "x" * 60


@pytest.fixture
def agent(cfg, tmp_path, monkeypatch):
    a = Agent(dataclasses.replace(cfg, data_dir=str(tmp_path)))
    a.calls = []
    monkeypatch.setattr(desktop, "stop_helpers", lambda command: a.calls.append(("stop", command)) or 1)
    monkeypatch.setattr(desktop, "start_in_user_session", lambda *args: a.calls.append(("start", *args)) or 4242)
    return a


def test_agent_replaces_pet_and_removes_it(agent, monkeypatch):
    monkeypatch.setattr("psutil.pid_exists", lambda pid: pid == 4242)

    async def scenario():
        ok, text, _ = await agent.execute("pet", {"mood": "angry", "text": "  Ko'p\n o'ynama  "})
        assert ok and text == "👁 Глаз: на экране"
        assert agent.status()["pet"] == "angry"
        assert (await agent.execute("pet_off", {}))[1] == "👁 Глаз: убран"
        assert not (await agent.execute("pet", {"mood": "dance"}))[0]

    asyncio.run(scenario())
    assert agent.calls == [("stop", "pet"), ("start", "pet", "angry", "--text", "Ko'p o'ynama"), ("stop", "pet")]
    assert agent.status()["pet"] == ""


def test_server_sends_pet_commands(server_cfg):
    server = Server(server_cfg)
    calls = []

    async def command(name, action, **args):
        calls.append((name, action, args))
        return CommandResult(True, "👁 Глаз: на экране")

    server.hub.command = command

    async def scenario():
        assert (await server.perform("pet_on", "HOME-PC", "happy")).startswith("✅")
        await server.perform("pet_say", "HOME-PC", "salom")
        await server.perform("pet_off", "HOME-PC")

    asyncio.run(scenario())
    assert calls == [("HOME-PC", "pet", {"mood": "happy"}), ("HOME-PC", "pet", {"mood": "watch", "text": "salom"}),
                     ("HOME-PC", "pet_off", {})]


def test_old_agent_gets_a_clear_message(server_cfg):
    server = Server(server_cfg)

    async def command(name, action, **args):
        return CommandResult(False, "неизвестная команда pet")

    server.hub.command = command
    assert "старый агент" in asyncio.run(server.perform("pet_on", "HOME-PC", "watch"))


def test_pet_screen(server_cfg):
    server = Server(server_cfg)
    agent = AgentLink("HOME-PC", ws=ONLINE, status={"pet": "watch"})
    server.hub.agents["HOME-PC"] = agent
    text, markup = asyncio.run(screens.build(server, "pet", "HOME-PC"))
    assert "Katta og'a seni kuzatyabdi" in text and "сейчас: 👀 Следит" in text
    buttons = [(b.text, b.callback_data) for row in markup.inline_keyboard for b in row]
    assert buttons[0][0] == "✅ 👀 Следит" and any("pet_off" in data for _, data in buttons)
    assert all(len(data) <= 64 for _, data in buttons)

    agent.status = {}
    assert not any("pet_off" in b.callback_data for row in kb.pet(agent).inline_keyboard for b in row)
