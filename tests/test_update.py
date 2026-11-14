from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import io
import sys

import pytest

from deepsec import update
from deepsec.agent import Agent
from deepsec.server import keyboards as kb
from deepsec.server.hub import AgentLink

ONLINE = type("WS", (), {"closed": False})()
PAYLOAD = b"MZ installer bytes"
URL = "https://github.com/abdurohman-karim/deepsec/releases/download/v0.7.0/DeepSecSetup-0.7.0.exe"


def asset(name="DeepSecSetup-0.7.0.exe", digest="sha256:" + hashlib.sha256(PAYLOAD).hexdigest(), url=URL):
    return {"name": name, "digest": digest, "browser_download_url": url}


def test_versions():
    assert update.is_newer("0.10.0", "0.9.9") and update.is_newer("0.6.0", "0.5.1")
    assert not update.is_newer("0.6.0", "0.6.0") and not update.is_newer("0.5.9", "0.6.0")


def test_release_needs_installer_with_digest_from_our_repo():
    release = update.release_from_json({"assets": [asset("notes.txt"), asset()]})
    assert release == update.Release("0.7.0", URL, hashlib.sha256(PAYLOAD).hexdigest(), "DeepSecSetup-0.7.0.exe")
    assert update.release_from_json({"assets": [asset(digest="")]}) is None  # без SHA-256 от GitHub не ставим
    evil = URL.replace("abdurohman-karim/deepsec", "someone/else")
    assert update.release_from_json({"assets": [asset(url=evil)]}) is None


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}


def fake_urlopen(monkeypatch, body: bytes):
    monkeypatch.setattr(update.urllib.request, "urlopen", lambda request, timeout: FakeResponse(body))


def test_download_checks_sha256(monkeypatch, tmp_path):
    release = update.release_from_json({"assets": [asset()]})
    fake_urlopen(monkeypatch, PAYLOAD)
    seen = []
    assert update.download(release, tmp_path, lambda done, total: seen.append((done, total))).read_bytes() == PAYLOAD
    assert seen[-1] == (len(PAYLOAD), len(PAYLOAD))  # прогресс для полосы загрузки в окне

    fake_urlopen(monkeypatch, PAYLOAD + b" tampered")
    with pytest.raises(update.UpdateError, match="SHA-256"):
        update.download(release, tmp_path / "again")
    assert not (tmp_path / "again" / release.name).exists()


def test_update_flow(monkeypatch, tmp_path):
    release = update.release_from_json({"assets": [asset()]})
    with pytest.raises(update.UpdateError, match="git pull"):
        update.update("0.6.0", str(tmp_path))  # из исходников

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(update, "latest_release", lambda repo: release)
    assert update.update("0.7.0", str(tmp_path)) == "уже последняя версия (0.7.0)"

    installed = []
    fake_urlopen(monkeypatch, PAYLOAD)
    monkeypatch.setattr(update, "install", lambda path, log_dir: installed.append(path.name))
    assert update.update("0.6.0", str(tmp_path)).startswith("0.6.0 → 0.7.0")
    assert installed == ["DeepSecSetup-0.7.0.exe"]


@pytest.fixture
def agent(cfg, tmp_path):
    return Agent(dataclasses.replace(cfg, data_dir=str(tmp_path)))


def test_agent_reports_new_version(agent, monkeypatch):
    release = update.release_from_json({"assets": [asset()]})
    monkeypatch.setattr(update, "latest_release", lambda repo: release)
    ok, text, _ = asyncio.run(agent.execute("update_check", {}))
    assert ok and "доступна версия 0.7.0" in text and agent.status()["update"] == "0.7.0"

    def broken(repo):
        raise ValueError("garbage from GitHub")

    monkeypatch.setattr(update, "latest_release", broken)
    ok, text, _ = asyncio.run(agent.execute("update_check", {}))
    assert not ok and "не удалось" in text  # ошибка проверки не роняет агента


@pytest.fixture
def frozen_updater(monkeypatch, tmp_path):
    """Updater с подменой сети и установщика: загрузка пишет файл и сообщает прогресс."""
    release = update.release_from_json({"assets": [asset()]})
    installed = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(update, "latest_release", lambda repo: release)

    def fake_download(rel, folder, progress):
        folder.mkdir(parents=True, exist_ok=True)
        progress(5, 10)
        progress(10, 10)
        (folder / rel.name).write_bytes(PAYLOAD)
        return folder / rel.name

    monkeypatch.setattr(update, "download", fake_download)
    monkeypatch.setattr(update, "install", lambda path, folder: installed.append(path.name))
    changes = []
    updater = update.Updater("0.6.2", str(tmp_path), on_change=lambda: changes.append(1))
    updater.installed = installed
    return updater


async def wait_state(updater, state):
    for _ in range(100):
        if updater.state == state:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"{updater.state} != {state}")


def test_window_flow_download_then_restart(frozen_updater, tmp_path):
    u = frozen_updater

    async def scenario():
        await u.check()
        assert u.snapshot()["available"] == "0.7.0" and u.state == "available"
        assert u.start(install_after=False)
        await wait_state(u, "ready")
        assert (u.done, u.total) == (10, 10) and u.installed == []  # без «Перезапустить» не ставим
        await u.install(reopen_window=True)
        assert u.state == "installing" and u.installed == ["DeepSecSetup-0.7.0.exe"]

    asyncio.run(scenario())
    assert update.take_reopen_flag(str(tmp_path)) == "0.6.2"  # новый агент откроет окно и скажет «обновлено»
    assert update.take_reopen_flag(str(tmp_path)) is None


def test_install_before_download_is_refused(frozen_updater):
    with pytest.raises(update.UpdateError, match="сначала скачайте"):
        asyncio.run(frozen_updater.install())


def test_local_channel_only_for_the_window(frozen_updater):
    from aiohttp.test_utils import TestClient, TestServer

    from deepsec.control import build_app
    from deepsec.protocol import LOCAL_HEADER

    async def scenario():
        async with TestClient(TestServer(build_app(frozen_updater))) as client:
            assert (await client.get("/update")).status == 403  # без заголовка окна
            page = await client.post("/update/check", headers={LOCAL_HEADER: "1", "Origin": "https://evil.example"})
            assert page.status == 403  # запрос со страницы в браузере
            snap = await (await client.post("/update/check", headers={LOCAL_HEADER: "1"})).json()
            assert snap["available"] == "0.7.0"
            early = await client.post("/update/install", headers={LOCAL_HEADER: "1"})
            assert early.status == 409
            await client.post("/update/download", headers={LOCAL_HEADER: "1"})
            await wait_state(frozen_updater, "ready")
            snap = await (await client.post("/update/install", headers={LOCAL_HEADER: "1"})).json()
            assert snap["state"] == "installing"

    asyncio.run(scenario())


def test_bot_update_downloads_and_installs_in_background(agent, monkeypatch, frozen_updater):
    agent.updater = frozen_updater

    async def scenario():
        ok, text, _ = await agent.execute("update", {})
        assert ok and "0.7.0" in text
        await wait_state(agent.updater, "installing")

    asyncio.run(scenario())
    assert agent.updater.installed == ["DeepSecSetup-0.7.0.exe"]


def test_bot_offers_update_only_when_available():
    agent = AgentLink("HOME-PC", ws=ONLINE, status={"update": "0.7.0"})
    labels = {b.callback_data.split(":")[1]: b.text for row in kb.pc(agent).inline_keyboard for b in row}
    assert labels["update"] == "⬆️ Установить агента 0.7.0" and "update_check" not in labels
    agent.status = {}
    assert "update_check" in {b.callback_data.split(":")[1] for row in kb.pc(agent).inline_keyboard for b in row}
    agent.status = {"update": "0.7.0", "update_state": "downloading"}  # идёт само — кнопок нет
    assert not {"update", "update_check"} & {b.callback_data.split(":")[1]
                                             for row in kb.pc(agent).inline_keyboard for b in row}
