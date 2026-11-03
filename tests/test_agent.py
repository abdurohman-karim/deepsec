from __future__ import annotations

import asyncio
import dataclasses

import pytest

from deepsec import agent as agent_module
from deepsec import response
from deepsec.agent import Agent
from deepsec.incidents import Incident, Kind, Severity

STEALER = r"C:\Users\me\Downloads\crack.exe"


class FakeLink:
    def __init__(self) -> None:
        self.sent: list[tuple[Incident, bool]] = []

    def send_incident(self, inc: Incident, armed: bool) -> None:
        self.sent.append((inc, armed))

    def push_status(self) -> None:
        pass


@pytest.fixture
def agent(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(agent_module, "NOTIFY_DELAY", 0.05)
    a = Agent(dataclasses.replace(cfg, data_dir=str(tmp_path)))
    a.link = FakeLink()
    a.calls = []
    monkeypatch.setattr(response, "kill_tree", lambda pid, path: a.calls.append(("kill", pid)) or "убит")
    monkeypatch.setattr(response, "block_program", lambda path: a.calls.append(("block", path)) or "DeepSec-Block-x")
    monkeypatch.setattr(response, "unblock", lambda rule: a.calls.append(("unblock", rule)))
    return a


def stealer_read(file: str, path: str = STEALER) -> Incident:
    return Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=99, process_path=path, files=[file], respond=True)


async def read_two_files(agent: Agent) -> None:
    await agent.handle(stealer_read("key_datas"))
    await agent.handle(stealer_read("D877F783D5D3EF8Cs"))
    await asyncio.sleep(0.2)


def test_armed_agent_kills_blocks_merges_and_reports(agent):
    asyncio.run(read_two_files(agent))
    assert agent.calls == [("kill", 99), ("block", STEALER)]  # реакция один раз, а не на каждый файл
    (inc, armed), = agent.link.sent
    assert armed and inc.host == "HOME-PC"
    assert inc.files == ["key_datas", "D877F783D5D3EF8Cs"]
    assert inc.actions == ["🔪 Процесс: убит", "🧱 Брандмауэр: сеть запрещена (правило DeepSec-Block-x)"]
    assert agent.state.blocked == {"DeepSec-Block-x": STEALER}
    assert agent.journal.get(inc.id) is inc


def test_disarmed_agent_only_reports(agent):
    agent.state.armed = False
    asyncio.run(read_two_files(agent))
    assert agent.calls == []
    (inc, armed), = agent.link.sent
    assert not armed and inc.actions == []


def test_response_errors_are_reported_not_raised(agent, monkeypatch):
    def broken(path):
        raise response.ResponseError("netsh: доступ запрещён")

    monkeypatch.setattr(response, "block_program", broken)
    asyncio.run(read_two_files(agent))
    assert agent.link.sent[0][0].actions[1] == "🧱 Брандмауэр: ошибка — netsh: доступ запрещён"


def test_never_blocks_agents_own_interpreter(agent):
    async def scenario():
        await agent.handle(stealer_read("key_datas", path=agent.own_exe))
        await asyncio.sleep(0.2)

    asyncio.run(scenario())
    assert agent.calls == [("kill", 99)]
    assert "интерпретатор самого агента" in agent.link.sent[0][0].actions[1]


def test_server_commands(agent):
    async def scenario():
        assert (await agent.execute("disarm", {}))[0] and not agent.state.armed
        assert (await agent.execute("arm", {}))[0] and agent.state.armed
        ok, text, _ = await agent.execute("block", {"path": STEALER})
        assert ok and "DeepSec-Block-x" in text
        ok, text, _ = await agent.execute("unblock", {"rule": "*"})
        assert ok and agent.state.blocked == {}
        assert not (await agent.execute("format_c", {}))[0]

    asyncio.run(scenario())
    assert agent.status()["armed"] and agent.status()["blocked"] == {}
