from __future__ import annotations

import asyncio

from aiogram.types import InlineKeyboardMarkup

from deepsec.incidents import Incident, Kind, Severity
from deepsec.server import keyboards as kb
from deepsec.server import screens, texts
from deepsec.server.core import Server
from deepsec.server.hub import AgentLink

STATUS = {"armed": True, "isolated": False, "audit_ok": True, "blocked": {"DeepSec-Block-1": r"C:\x\crack.exe"},
          "trusted_exes": 0, "tdata": 1, "decoys": 3, "version": "0.2.0", "started": "2026-11-03T10:00:00+00:00"}


def actions(markup: InlineKeyboardMarkup | None) -> list[str]:
    if markup is None:
        return []
    return [b.callback_data.split(":")[1] for row in markup.inline_keyboard for b in row]


def callbacks_fit(markup: InlineKeyboardMarkup | None) -> bool:
    return markup is None or all(len(b.callback_data) <= 64 for row in markup.inline_keyboard for b in row)


def test_incident_text_is_escaped_and_has_hint():
    inc = Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "Чужой процесс <b>", pid=1234,
                   process_path=r"C:\Users\me\x<y>.exe", files=[rf"C:\t\f{i}" for i in range(7)], host="HOME-PC")
    text = texts.incident(inc)
    assert "&lt;b&gt;" in text and "x&lt;y&gt;.exe" in text and "(+2)" in text and "🖥 HOME-PC" in text
    assert "📵 Завершить сеансы" in text


def test_alert_keyboard_for_theft():
    inc = Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=1234, process_path=r"C:\x.exe", host="HOME-PC")
    assert actions(kb.alert(inc)) == ["terminate", "kill", "block", "quarantine", "lock", "isolate", "trust"]
    assert actions(kb.alert(inc, "isolate")) == ["isolate_ok", "back"]
    assert callbacks_fit(kb.alert(inc))

    inc.actions.append("📵 Сеансы: завершаю все сеансы аккаунта, кроме доверенных…")
    assert "terminate" not in actions(kb.alert(inc))
    assert "завершаются автоматически" in texts.incident(inc)


def test_alert_keyboard_variants():
    login = Incident(Kind.NEW_LOGIN, Severity.WARNING, "вход", session=-1234567890123456789)
    assert actions(kb.alert(login)) == ["login_kill"]
    assert kb.alert(Incident(Kind.LOCAL_LOGON, Severity.INFO, "вход", host="HOME-PC")) is None
    assert kb.alert(Incident(Kind.AGENT_OFFLINE, Severity.WARNING, "нет связи", host="HOME-PC")) is None


def test_menu_screens(server_cfg):
    server = Server(server_cfg)
    agent = AgentLink("HOME-PC", status=STATUS, last_seen=1.0)
    server.hub.agents["HOME-PC"] = agent

    text, markup = asyncio.run(screens.build(server, "home"))
    assert "HOME-PC" in text and "не на связи" in text
    assert actions(markup)[:3] == ["pc", "incidents", "sessions"]

    agent.ws = type("WS", (), {"closed": False})()  # «на связи»
    text, markup = asyncio.run(screens.build(server, "pc", "HOME-PC", notice="✅ готово"))
    assert text.startswith("✅ готово") and "авто-реакция" in text
    assert actions(markup) == ["shot", "apps", "pet", "lock","confirm_isolate", "disarm", "blocks", "selftest", "pc", "home"]

    text, markup = asyncio.run(screens.build(server, "blocks", "HOME-PC"))
    assert "crack.exe" in text and actions(markup) == ["unblock", "pc"]
    assert all(callbacks_fit(m) for m in (markup, kb.home(server), kb.pc(agent)))


def test_code_actions_are_marked_with_key():
    agent = AgentLink("HOME-PC", status={**STATUS, "isolated": True})
    agent.ws = type("WS", (), {"closed": False})()
    labels = {b.callback_data.split(":")[1]: b.text for row in kb.pc(agent).inline_keyboard for b in row}
    assert labels["unisolate"].endswith("🔑") and labels["disarm"].endswith("🔑")
    assert set(texts.CODE_LABELS) >= {"disarm", "unisolate", "unblock", "trust", "sess_trust", "lockdown_off"}
