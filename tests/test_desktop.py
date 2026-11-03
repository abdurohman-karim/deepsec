from __future__ import annotations

import asyncio
import base64
import dataclasses

import pytest

from deepsec import desktop
from deepsec.agent import Agent
from deepsec.server import keyboards as kb
from deepsec.server import screens, texts
from deepsec.server.core import Server
from deepsec.server.hub import CommandResult

APPS = {
    "user": "me", "locked": False, "idle": 600.0,
    "active": {"title": "YouTube — Google Chrome", "exe": "chrome.exe", "active": True},
    "windows": [
        {"title": "YouTube — Google Chrome", "exe": "chrome.exe", "pid": 10, "minimized": False, "active": True},
        {"title": "<script> & co", "exe": "notepad.exe", "pid": 11, "minimized": True, "active": False},
    ],
    "background": ["steam.exe", "Discord.exe"],
}


def test_parse_output_takes_last_json_line():
    assert desktop.parse_output(b'warning from a library\r\n{"user": "me"}\r\n') == {"user": "me"}
    with pytest.raises(desktop.DesktopError):
        desktop.parse_output(b"Traceback ...")
    with pytest.raises(desktop.DesktopError):
        desktop.parse_output(b"")


def test_background_skips_windows_processes_and_windowed_apps():
    processes = [
        ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
        ("steam.exe", r"C:\Program Files (x86)\Steam\steam.exe"),
        ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        ("Discord.exe", r"C:\Users\me\AppData\Local\Discord\Discord.exe"),
        ("Discord.exe", r"C:\Users\me\AppData\Local\Discord\Discord.exe"),
        ("secret.exe", ""),  # путь недоступен — не показываем
    ]
    assert desktop.background_names(processes, {"chrome.exe"}, r"C:\Windows") == ["Discord.exe", "steam.exe"]


def test_helper_command_from_sources():
    cmd, _ = desktop.helper_command("apps")
    assert cmd[-4:] == ["-m", "deepsec", "desktop", "apps"] and not cmd[0].lower().endswith("pythonw.exe")


@pytest.fixture
def agent(cfg, tmp_path):
    return Agent(dataclasses.replace(cfg, data_dir=str(tmp_path)))


def test_agent_returns_desktop_data_and_errors(agent, monkeypatch):
    replies = iter([{"user": "me", "jpeg": "AAAA"}, {"user": "me", "locked": True, "error": "экран заблокирован"}])

    def fake(what):
        if what == "apps":
            raise desktop.DesktopError("за компьютером никто не работает")
        return next(replies)

    monkeypatch.setattr(desktop, "run_in_user_session", fake)

    async def scenario():
        assert await agent.execute("screenshot", {}) == (True, "", {"user": "me", "jpeg": "AAAA"})
        assert await agent.execute("screenshot", {}) == (False, "экран заблокирован", {"user": "me", "locked": True})
        assert await agent.execute("apps", {}) == (False, "за компьютером никто не работает", None)

    asyncio.run(scenario())


def test_server_decodes_screenshot(server_cfg):
    server = Server(server_cfg)
    jpeg = b"\xff\xd8 fake jpeg"

    async def command(name, action, **args):
        assert (name, action) == ("HOME-PC", "screenshot")
        return CommandResult(True, "", {"jpeg": base64.b64encode(jpeg).decode(), "user": "me"})

    server.hub.command = command
    image, result = asyncio.run(server.screenshot("HOME-PC"))
    assert image == jpeg and result.data["user"] == "me"


def test_apps_screen_is_escaped_and_marks_windows(server_cfg):
    server = Server(server_cfg)

    async def command(name, action, **args):
        return CommandResult(True, "", APPS)

    server.hub.command = command
    text, markup = asyncio.run(screens.build(server, "apps", "HOME-PC"))
    assert "▶️ YouTube — Google Chrome" in text and "➖ &lt;script&gt; &amp; co" in text
    assert "Без действий 10 мин" in text and "Discord.exe" in text
    assert [b.callback_data.split(":")[1] for row in markup.inline_keyboard for b in row] == ["shot", "apps", "pc"]


def test_long_apps_list_fits_telegram_limit():
    many = {**APPS, "windows": [{"title": "x" * 100, "exe": "a.exe"} for _ in range(100)]}
    text = texts.apps("HOME-PC", CommandResult(True, "", many))
    assert len(text) <= 4096 and text.endswith("…")


def test_desktop_failures_and_caption():
    locked = CommandResult(False, "экран заблокирован", {"user": "me", "locked": True, "idle": 900})
    assert texts.desktop_failure(locked) == "⚠️ экран заблокирован · пользователь me"
    assert "компьютер не на связи" in texts.apps("HOME-PC", CommandResult(False, "компьютер не на связи"))
    caption = texts.screenshot_caption("HOME-PC", {**APPS, "idle": 5})
    assert "Работают прямо сейчас" in caption and "chrome.exe" in caption
    assert all(len(b.callback_data) <= 64 for row in kb.apps("HOME-PC").inline_keyboard for b in row)
