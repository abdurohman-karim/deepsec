from __future__ import annotations

import sys

import pytest

from deepsec import setup_win
from deepsec.__main__ import main
from deepsec.setup_win import SetupError, SetupOptions, launch_target, server_settings


def test_installer_flags_build_connection():
    env = server_settings({}, SetupOptions(server=" IP_СЕРВЕРА ", port="8444",
                                           fingerprint="AB:CD:EF", token=" tok ", yes=True))
    assert env["SERVER_URL"] == "wss://IP_СЕРВЕРА:8444/agent"
    assert env["SERVER_FINGERPRINT"] == "abcdef" and env["AGENT_TOKEN"] == "tok"
    assert env["AGENT_NAME"]  # по умолчанию — имя компьютера


def test_upgrade_keeps_previous_settings_when_fields_are_empty():
    old = {"SERVER_URL": "wss://1.2.3.4:8444/agent", "SERVER_FINGERPRINT": "aa", "AGENT_TOKEN": "t",
           "AGENT_NAME": "Home"}
    assert server_settings(old, SetupOptions(yes=True)) == old
    assert server_settings(old, SetupOptions(token="new", yes=True))["AGENT_TOKEN"] == "new"


def test_installer_without_server_data_fails_clearly():
    with pytest.raises(SetupError, match="SERVER_FINGERPRINT, AGENT_TOKEN"):
        server_settings({}, SetupOptions(server="1.2.3.4", yes=True))


def test_scheduled_task_target(monkeypatch, tmp_path):
    exe, args, workdir = launch_target()
    assert args == "-m deepsec run"

    frozen_exe = tmp_path / "DeepSec" / "DeepSecAgent.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(frozen_exe))
    assert launch_target() == (str(frozen_exe), "run", str(frozen_exe.parent))


def test_pause_shows_error_instead_of_crashing(monkeypatch, capsys):
    def broken(opts):
        raise SetupError("tdata не найдена")

    monkeypatch.setattr(setup_win, "setup", broken)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert main(["setup", "--yes", "--pause"]) == 1
    assert "⛔ Ошибка: tdata не найдена" in capsys.readouterr().out
