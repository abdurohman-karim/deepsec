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


def fake_urlopen(monkeypatch, body: bytes):
    monkeypatch.setattr(update.urllib.request, "urlopen", lambda request, timeout: io.BytesIO(body))


def test_download_checks_sha256(monkeypatch, tmp_path):
    release = update.release_from_json({"assets": [asset()]})
    fake_urlopen(monkeypatch, PAYLOAD)
    assert update.download(release, tmp_path).read_bytes() == PAYLOAD

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


def test_bot_offers_update_only_when_available():
    agent = AgentLink("HOME-PC", ws=ONLINE, status={"update": "0.7.0"})
    labels = {b.callback_data.split(":")[1]: b.text for row in kb.pc(agent).inline_keyboard for b in row}
    assert labels["update"] == "⬆️ Установить агента 0.7.0" and "update_check" not in labels
    agent.status = {}
    assert "update_check" in {b.callback_data.split(":")[1] for row in kb.pc(agent).inline_keyboard for b in row}
