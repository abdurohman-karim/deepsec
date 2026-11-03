from __future__ import annotations

import asyncio

import pytest

from deepsec.incidents import Incident, Kind, Severity
from deepsec.server.core import Server
from deepsec.server.guard import GuardTooFresh, SessionInfo
from deepsec.server.hub import AgentLink, CommandResult
from deepsec.totp import MAX_FAILURES


class FakeNotifier:
    def __init__(self) -> None:
        self.incidents: list[Incident] = []
        self.messages: list[str] = []

    def send(self, text, markup=None, silent=False) -> None:
        self.messages.append(text)

    def incident(self, inc: Incident) -> None:
        self.incidents.append(inc)


class FakeGuard:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.terminated_except: list[set] = []
        self.terminated: list[int] = []

    async def terminate_except(self, keep):
        if self.error:
            raise self.error
        self.terminated_except.append(set(keep))
        return [SessionInfo(2, False, "Telegram Desktop", "PC", "Russia", None)]

    async def terminate(self, session_hash):
        self.terminated.append(session_hash)

    async def sessions(self):
        return [SessionInfo(1, True, "DeepSec", "", "", None), SessionInfo(3, False, "Telegram iOS", "iPhone", "", None)]


@pytest.fixture
def server(server_cfg):
    s = Server(server_cfg, FakeNotifier())
    s.guard = FakeGuard()
    return s


def theft(armed_respond: bool = True) -> Incident:
    return Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=99, process_path=r"C:\crack.exe",
                    respond=armed_respond)


async def settle(coro=None):
    if coro is not None:
        await coro
    await asyncio.sleep(0.05)


def test_theft_from_armed_agent_terminates_sessions_and_starts_lockdown(server):
    server.state.trusted_sessions["3"] = "iPhone"
    asyncio.run(settle(server.on_incident(AgentLink("HOME-PC"), theft(), armed=True)))

    assert server.guard.terminated_except == [{3}]  # доверенный телефон не трогаем
    inc = server.notifier.incidents[0]
    assert inc.host == "HOME-PC" and inc.actions[-1].startswith("📵 Сеансы: завершаю")
    assert server.state.pending_terminate == "" and server.lockdown_active
    assert any("Сеансы аккаунта завершены автоматически" in m for m in server.notifier.messages)


def test_disarmed_agent_does_not_trigger_termination(server):
    asyncio.run(settle(server.on_incident(AgentLink("HOME-PC"), theft(), armed=False)))
    assert server.guard.terminated_except == []
    assert len(server.notifier.incidents) == 1


def test_resent_incident_is_ignored(server):
    inc = theft()

    async def scenario():
        await server.on_incident(AgentLink("HOME-PC"), inc, armed=False)
        await server.on_incident(AgentLink("HOME-PC"), Incident.from_json(inc.to_json()), armed=False)

    asyncio.run(scenario())
    assert len(server.notifier.incidents) == 1


def test_disconnected_guard_keeps_termination_pending(server):
    server.guard, server.guard_problem = None, "нет связи"
    asyncio.run(settle(server.on_incident(AgentLink("HOME-PC"), theft(), armed=True)))
    assert "сторож не работает" in server.notifier.incidents[0].actions[-1]
    assert server.state.pending_terminate  # выполнится, когда сторож подключится


def test_too_fresh_guard_warns_and_keeps_pending(server):
    server.guard = FakeGuard(GuardTooFresh("младше 24 часов"))
    asyncio.run(settle(server.on_incident(AgentLink("HOME-PC"), theft(), armed=True)))
    assert server.state.pending_terminate and not server.lockdown_active
    assert any(i.kind is Kind.GUARD for i in server.notifier.incidents)


def test_new_login_during_lockdown_is_terminated(server):
    server.state.lockdown_until = 10**12
    asyncio.run(server.on_new_login(777, "Samsung · Netherlands"))
    assert server.guard.terminated == [777]
    inc = server.notifier.incidents[0]
    assert inc.severity is Severity.CRITICAL and inc.session == 777


def test_new_login_outside_lockdown_only_alerts(server):
    asyncio.run(server.on_new_login(777, "Samsung"))
    assert server.guard.terminated == []
    assert server.notifier.incidents[0].kind is Kind.NEW_LOGIN


def test_totp_bruteforce_terminates_sessions(server):
    async def scenario():
        for _ in range(MAX_FAILURES):
            server.check_totp("000000")
        await asyncio.sleep(0.05)

    asyncio.run(scenario())
    assert server.guard.terminated_except == [set()]
    assert server.notifier.incidents[0].kind is Kind.TOTP_BRUTEFORCE


def test_incident_action_goes_to_its_computer(server):
    calls = []

    async def command(name, action, **args):
        calls.append((name, action, args))
        return CommandResult(True, "🔪 Процесс: завершено процессов: 1")

    server.hub.command = command
    inc = theft()
    inc.host = "HOME-PC"
    server.journal.add(inc)
    notice = asyncio.run(server.perform("kill", inc.id))
    assert calls == [("HOME-PC", "kill", {"pid": 99, "path": r"C:\crack.exe"})]
    assert notice.startswith("✅") and inc.actions == ["🔪 Процесс: завершено процессов: 1"]


def test_session_trust_by_index(server):
    async def scenario():
        await server.list_sessions()
        return await server.perform("sess_trust", "1")

    assert "Доверенный" in asyncio.run(scenario())
    assert server.state.trusted_sessions == {"3": "Telegram iOS · iPhone"}


def test_offline_agent_alert(server, monkeypatch):
    from deepsec.server import core

    monkeypatch.setattr(core, "OFFLINE_CHECK_INTERVAL", 0.01)
    server.hub.agents["HOME-PC"] = AgentLink("HOME-PC", last_seen=1.0)

    async def scenario():
        task = asyncio.ensure_future(server.watch_agents())
        await asyncio.sleep(0.05)
        task.cancel()

    asyncio.run(scenario())
    (inc,) = server.notifier.incidents  # одно уведомление, без повторов
    assert inc.kind is Kind.AGENT_OFFLINE and inc.host == "HOME-PC"
