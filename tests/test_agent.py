from __future__ import annotations

import asyncio
import dataclasses
from types import SimpleNamespace

import pytest

from deepsec import agent as agent_module
from deepsec import response
from deepsec.agent import Agent
from deepsec.incidents import Incident, Kind, Severity

STEALER = r"C:\Users\me\Downloads\crack.exe"


@pytest.fixture
def agent(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(agent_module, "NOTIFY_DELAY", 0.05)
    a = Agent(dataclasses.replace(cfg, data_dir=str(tmp_path)))
    a.sent = []
    a.notifier = SimpleNamespace(incident=a.sent.append, send=lambda *args, **kwargs: None)
    a.calls = []
    monkeypatch.setattr(response, "kill_tree", lambda pid, path: a.calls.append(("kill", pid)) or "убит")
    monkeypatch.setattr(response, "block_program", lambda path: a.calls.append(("block", path)) or "DeepSec-Block-x")
    return a


def stealer_read(file: str) -> Incident:
    return Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=99, process_path=STEALER, files=[file], respond=True)


async def read_two_files(agent: Agent) -> None:
    await agent.handle(stealer_read("key_datas"))
    await agent.handle(stealer_read("D877F783D5D3EF8Cs"))
    await asyncio.sleep(0.2)


def test_armed_agent_kills_blocks_and_merges(agent):
    asyncio.run(read_two_files(agent))
    assert agent.calls == [("kill", 99), ("block", STEALER)]  # реакция один раз, а не на каждый файл
    assert len(agent.sent) == 1
    assert agent.sent[0].files == ["key_datas", "D877F783D5D3EF8Cs"]
    assert agent.sent[0].actions == ["🔪 Процесс: убит", "🧱 Брандмауэр: сеть запрещена (правило DeepSec-Block-x)"]
    assert agent.state.blocked == {"DeepSec-Block-x": STEALER}
    assert agent.journal.get(agent.sent[0].id) is agent.sent[0]


def test_disarmed_agent_only_notifies(agent):
    agent.set_armed(False)
    asyncio.run(read_two_files(agent))
    assert agent.calls == []
    assert len(agent.sent) == 1 and agent.sent[0].actions == []


def test_response_errors_are_reported_not_raised(agent, monkeypatch):
    def broken(path):
        raise response.ResponseError("netsh: доступ запрещён")

    monkeypatch.setattr(response, "block_program", broken)
    asyncio.run(read_two_files(agent))
    assert agent.sent[0].actions[1] == "🧱 Брандмауэр: ошибка — netsh: доступ запрещён"


def test_never_blocks_agents_own_interpreter(agent):
    async def scenario():
        await agent.handle(Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=99,
                                    process_path=agent.own_exe, files=["key_datas"], respond=True))
        await asyncio.sleep(0.2)

    asyncio.run(scenario())
    assert agent.calls == [("kill", 99)]
    assert "интерпретатор самого агента" in agent.sent[0].actions[1]
