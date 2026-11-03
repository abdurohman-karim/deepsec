from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pyotp
import pytest
from conftest import event_xml

from deepsec.config import Config, ConfigError, parse_trusted
from deepsec.incidents import Incident, Kind, Severity
from deepsec.monitors.processes import RemoteToolWatcher
from deepsec.state import AgentState, Journal
from deepsec.totp import MAX_FAILURES, TotpGuard
from deepsec.trust import Signature, TrustChecker, parse_subject, signer_matches
from deepsec.winevent import parse_event_xml


def test_parse_event_xml():
    ev = parse_event_xml(event_xml(4663, ObjectName=r"C:\x\key_datas", ProcessId="0x10"))
    assert ev.event_id == 4663 and ev.record_id == 42
    assert ev.get("ObjectName") == r"C:\x\key_datas"
    assert ev.get("Missing") == ""
    assert ev.time == datetime(2026, 11, 3, 10, 15, 30, 123456, tzinfo=timezone.utc)


def test_parse_trusted():
    trusted = parse_trusted("Telegram.exe=Telegram FZ-LLC|Telegram Messenger LLP; MsMpEng.exe=Microsoft Corporation")
    assert trusted["telegram.exe"] == {"Telegram FZ-LLC", "Telegram Messenger LLP"}
    assert trusted["msmpeng.exe"] == {"Microsoft Corporation"}


def test_config_requires_keys():
    with pytest.raises(ConfigError, match="SERVER_FINGERPRINT"):
        Config.from_mapping({"SERVER_URL": "wss://1.2.3.4:8443/agent", "AGENT_TOKEN": "t", "TDATA_DIRS": r"C:\t"})
    cfg = Config.from_mapping({
        "SERVER_URL": "wss://1.2.3.4:8443/agent", "SERVER_FINGERPRINT": "AB:CD", "AGENT_TOKEN": "t",
        "TDATA_DIRS": r"C:\a;C:\b", "AUTO_LOCK": "yes", "AGENT_NAME": "Work",
    })
    assert cfg.tdata_dirs == (r"C:\a", r"C:\b") and cfg.auto_lock and cfg.auto_kill and cfg.agent_name == "Work"


def test_server_config_requires_keys():
    from deepsec.server.config import ServerConfig

    with pytest.raises(ConfigError, match="AGENT_TOKEN"):
        ServerConfig.from_mapping({"BOT_TOKEN": "x", "OWNER_ID": "1", "TOTP_SECRET": "s"})


def test_normalize_fingerprint():
    from deepsec.protocol import normalize_fingerprint

    assert normalize_fingerprint("sha256 Fingerprint=AB:CD:0F") == "abcd0f"


def test_outbox_survives_restart(tmp_path):
    from deepsec.state import Outbox

    box = Outbox(tmp_path / "outbox.json", limit=2)
    for key in ("a", "b", "c"):
        box.add(key, {"n": key})
    box.ack("b")
    assert Outbox(tmp_path / "outbox.json").items() == [("c", {"n": "c"})]


def test_parse_subject_with_quoted_commas():
    subject = 'CN=Telegram FZ-LLC, O="Telegram, FZ-LLC", L=Dubai, C=AE'
    assert parse_subject(subject) == {"CN": "Telegram FZ-LLC", "O": "Telegram, FZ-LLC", "L": "Dubai", "C": "AE"}
    assert signer_matches("CN=Microsoft Windows Publisher, O=Microsoft Corporation", {"Microsoft Corporation"})
    assert not signer_matches("CN=Telegram FZ-LLC Fake, O=Evil Ltd", {"Telegram FZ-LLC"})


def test_trust_checker_requires_valid_signature_from_allowed_org(tmp_path):
    exe = tmp_path / "Telegram.exe"
    exe.write_bytes(b"MZ")
    calls = []

    async def reader(path: str) -> Signature:
        calls.append(path)
        return Signature("Valid", "CN=Telegram FZ-LLC, O=Telegram FZ-LLC")

    checker = TrustChecker(parse_trusted("Telegram.exe=Telegram FZ-LLC"), signature_reader=reader)
    assert asyncio.run(checker(str(exe)))
    assert asyncio.run(checker(str(exe)))
    assert len(calls) == 1  # закэшировано

    stealer = tmp_path / "crack.exe"
    stealer.write_bytes(b"MZ")
    assert not asyncio.run(checker(str(stealer)))
    assert len(calls) == 1  # имени нет в списке — PowerShell даже не запускали


def test_trust_checker_rejects_renamed_unsigned_exe(tmp_path):
    fake = tmp_path / "Telegram.exe"
    fake.write_bytes(b"MZ")

    async def reader(path: str) -> Signature:
        return Signature("NotSigned", "")

    checker = TrustChecker(parse_trusted("Telegram.exe=Telegram FZ-LLC"), signature_reader=reader)
    assert not asyncio.run(checker(str(fake)))


def test_trust_checker_pinned_hash(tmp_path):
    from deepsec.trust import sha256_file

    tool = tmp_path / "backup.exe"
    tool.write_bytes(b"MZ backup")
    pinned: set[str] = set()
    checker = TrustChecker({}, pinned_hashes=lambda: pinned)
    assert not asyncio.run(checker(str(tool)))
    pinned.add(sha256_file(str(tool)))
    checker.invalidate()
    assert asyncio.run(checker(str(tool)))


def test_totp_guard_lockout_and_replay():
    secret = pyotp.random_base32()
    now = [1_800_000_000.0]
    guard = TotpGuard(secret, clock=lambda: now[0])
    code = pyotp.TOTP(secret).at(now[0])

    assert guard.check(code).ok
    assert not guard.check(code).ok  # повторно тот же код нельзя

    results = [guard.check("000000") for _ in range(MAX_FAILURES)]
    assert results[-1].locked_now and not any(r.locked_now for r in results[:-1])
    now[0] += 30
    assert not guard.check(pyotp.TOTP(secret).at(now[0])).ok  # даже верный код во время блокировки


def test_remote_tool_watcher_reports_only_new():
    procs = [(10, "AnyDesk.exe", r"C:\a\AnyDesk.exe"), (11, "notepad.exe", r"C:\n.exe")]
    watcher = RemoteToolWatcher(iter_processes=lambda: procs)
    first = watcher.poll()
    assert [(p.pid, p.tool) for p in first] == [(10, "AnyDesk")]
    assert watcher.poll() == []
    procs.append((12, "rustdesk.exe", ""))
    assert [p.pid for p in watcher.poll()] == [12]


def test_state_and_journal_roundtrip(tmp_path):
    state = AgentState.load(tmp_path / "state.json")
    assert state.armed
    state.armed = False
    state.blocked["DeepSec-Block-1"] = r"C:\x.exe"
    state.save()
    assert AgentState.load(tmp_path / "state.json").blocked == {"DeepSec-Block-1": r"C:\x.exe"}

    journal = Journal(tmp_path / "incidents.jsonl")
    inc = Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=5, files=["a"])
    journal.add(inc)
    reloaded = Journal(tmp_path / "incidents.jsonl").get(inc.id)
    assert reloaded == inc
