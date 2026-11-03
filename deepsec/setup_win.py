"""Установка и удаление на Windows (от имени администратора).

Из исходников: python -m deepsec setup | uninstall
Из установщика: DeepSecAgent.exe setup --yes --server … --fingerprint … --token …
"""
from __future__ import annotations

import asyncio
import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import psutil
from dotenv import dotenv_values

from . import winacl
from .config import DEFAULT_DATA_DIR, DEFAULT_TRUSTED, PROJECT_DIR, parse_trusted, split_list
from .protocol import AGENT_PATH, normalize_fingerprint
from .trust import parse_subject, read_signature, signer_matches

TASK_NAME = "DeepSec Agent"
DEFAULT_PORT = "8443"
# Форки Telegram, которые ищут стилеры. Если вы ими не пользуетесь — любое чтение их tdata стопроцентно чужое.
DECOY_APPS = ("AyuGram Desktop", "Kotatogram Desktop", "64Gram Desktop")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_PS_REGISTER_TASK = r"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute $env:DEEPSEC_EXE -Argument $env:DEEPSEC_ARGS -WorkingDirectory $env:DEEPSEC_WORKDIR
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $env:DEEPSEC_TASK -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $env:DEEPSEC_TASK
"""


class SetupError(RuntimeError):
    pass


@dataclass
class SetupOptions:
    server: str = ""  # IP или домен сервера
    port: str = ""
    fingerprint: str = ""
    token: str = ""
    name: str = ""
    yes: bool = False  # без вопросов, ответы по умолчанию (так запускает установщик)


def _ask(prompt: str, default: bool, opts: SetupOptions) -> bool:
    if opts.yes:
        print(f"{prompt} → {'да' if default else 'нет'}")
        return default
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not answer else answer in {"y", "yes", "д", "да"}


def _is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def launch_target() -> tuple[str, str, str]:
    """(exe, аргументы, рабочая папка) для задачи планировщика — из установщика или из исходников."""
    if getattr(sys, "frozen", False):  # собрано PyInstaller
        exe = Path(sys.executable)
        return str(exe), "run", str(exe.parent)
    python = Path(sys.executable)
    if python.with_name("pythonw.exe").exists():
        python = python.with_name("pythonw.exe")  # без консольного окна
    return str(python), "-m deepsec run", str(PROJECT_DIR)


def find_tdata() -> list[Path]:
    candidates = [Path(os.environ["APPDATA"]) / "Telegram Desktop" / "tdata"]
    # Портативный Telegram хранит tdata рядом с exe — найдём по запущенным процессам.
    for p in psutil.process_iter(["name", "exe"]):
        if (p.info["name"] or "").lower() == "telegram.exe" and p.info["exe"]:
            candidates.append(Path(p.info["exe"]).parent / "tdata")
    found: dict[str, Path] = {}
    for c in candidates:
        if c.is_dir():
            found.setdefault(str(c.resolve()).lower(), c.resolve())
    return list(found.values())


def create_decoy(tdata: Path) -> None:
    account = tdata / "D877F783D5D3EF8C"
    account.mkdir(parents=True, exist_ok=True)
    for path, size in ((tdata / "key_datas", 328), (tdata / "D877F783D5D3EF8Cs", 1100),
                       (tdata / "settingss", 700), (account / "maps", 400)):
        path.write_bytes(b"TDF$" + os.urandom(size))


def check_telegram_signatures(tdata_dirs: list[Path], trusted: dict[str, frozenset[str]],
                              opts: SetupOptions | None) -> list[str]:
    """Проверяем, что ваш Telegram.exe подписан тем, кому мы доверяем, — иначе агент убьёт сам Telegram.
    opts=None — только показать (для check), без вопросов."""
    extra_signers = []
    for tdata in tdata_dirs:
        exe = tdata.parent / "Telegram.exe"
        if not exe.is_file():
            continue
        sig = asyncio.run(read_signature(str(exe)))
        org = parse_subject(sig.subject).get("O", "")
        print(f"  {exe}: подпись {sig.status}, издатель {org or sig.subject or '—'}")
        if sig.status != "Valid":
            print("  ⚠️  ПОДПИСЬ НЕВАЛИДНА. Это может быть подменённый Telegram.exe — переустановите с telegram.org!")
        elif not signer_matches(sig.subject, trusted.get("telegram.exe", frozenset())):
            if opts is None:
                print(f"  ⚠️  Издатель «{org}» не в списке доверенных — запустите setup, он предложит добавить")
            elif org and _ask(f"  Издатель «{org}» не в списке доверенных. Добавить?", True, opts):
                extra_signers.append(org)
    return extra_signers


def server_settings(existing: dict[str, str], opts: SetupOptions) -> dict[str, str]:
    """Параметры подключения: из флагов (перекрывают прежние), из старого .env или вопросом в консоли."""
    env: dict[str, str] = {}
    if opts.server:
        env["SERVER_URL"] = f"wss://{opts.server.strip()}:{(opts.port or DEFAULT_PORT).strip()}{AGENT_PATH}"
    if opts.fingerprint:
        env["SERVER_FINGERPRINT"] = normalize_fingerprint(opts.fingerprint)
    if opts.token:
        env["AGENT_TOKEN"] = opts.token.strip()
    if opts.name:
        env["AGENT_NAME"] = opts.name.strip()
    merged = {**existing, **env}

    # Повторная настройка из меню «Пуск»: показываем, куда агент подключается, — иначе неверный адрес
    # или порт из первой установки остался бы навсегда.
    if not env and not opts.yes and merged.get("SERVER_URL"):
        print(f"\nСейчас агент подключается к {merged['SERVER_URL']}")
        if not _ask("Оставить этот сервер?", True, opts):
            for key in ("SERVER_URL", "SERVER_FINGERPRINT", "AGENT_TOKEN"):
                merged.pop(key, None)

    missing = [k for k in ("SERVER_URL", "SERVER_FINGERPRINT", "AGENT_TOKEN") if not merged.get(k)]
    if missing and opts.yes:
        raise SetupError("не заданы данные сервера: " + ", ".join(missing) + ". Их печатает ./deploy.sh на сервере")
    if missing:
        print("\nДанные сервера показал ./deploy.sh при выкладке (их же можно посмотреть в .env на сервере).")
    if not merged.get("SERVER_URL"):
        host = input("Адрес сервера (IP или домен): ").strip()
        port = input(f"Порт агентов [{DEFAULT_PORT}]: ").strip() or DEFAULT_PORT
        merged["SERVER_URL"] = f"wss://{host}:{port}{AGENT_PATH}"
    if not merged.get("SERVER_FINGERPRINT"):
        merged["SERVER_FINGERPRINT"] = normalize_fingerprint(input("SHA-256 отпечаток сертификата сервера: "))
    if not merged.get("AGENT_TOKEN"):
        merged["AGENT_TOKEN"] = input("AGENT_TOKEN: ").strip()
    merged.setdefault("AGENT_NAME", platform.node())
    return merged


def write_env(path: Path, env: dict[str, str], tdata_dirs: list[Path], decoy_dirs: list[Path],
              extra_signers: list[str]) -> None:
    env = dict(env)
    env["TDATA_DIRS"] = ";".join(str(p) for p in tdata_dirs)
    env["DECOY_DIRS"] = ";".join(str(p) for p in decoy_dirs)
    if extra_signers:
        trusted = parse_trusted(env.get("TRUSTED_PROCESSES") or DEFAULT_TRUSTED)
        for name in ("telegram.exe", "updater.exe"):
            trusted[name] = trusted.get(name, frozenset()) | set(extra_signers)
        env["TRUSTED_PROCESSES"] = ";".join(f"{n}={'|'.join(sorted(s))}" for n, s in trusted.items())
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), "utf-8")


def _load_env(path: Path) -> dict[str, str]:
    return {k: v for k, v in dotenv_values(path).items() if v} if path.exists() else {}


def setup(opts: SetupOptions | None = None) -> int:
    opts = opts or SetupOptions()
    if not _is_admin():
        print("Запустите от имени администратора.")
        return 1

    exe, args, workdir = launch_target()
    home = str(Path(os.environ["USERPROFILE"])).lower()
    if exe.lower().startswith(home) or workdir.lower().startswith(home):
        print("⚠️  Агент лежит в папке пользователя. Он работает от SYSTEM, поэтому вирус без прав\n"
              "   администратора сможет подменить его код и получить SYSTEM. Рекомендуется C:\\Program Files\\DeepSec.")
        if not _ask("Продолжить всё равно?", False, opts):
            return 1

    data_dir = Path(DEFAULT_DATA_DIR)
    env_path = data_dir / ".env"
    existing_env = _load_env(env_path)
    connection = server_settings(existing_env, opts)  # сначала — чтобы не настраивать аудит зря

    print("1/6 Ищу tdata…")
    tdata_dirs = find_tdata()
    if not tdata_dirs:
        raise SetupError("tdata не найдена. Запустите Telegram Desktop и повторите (меню «Пуск» → «Настроить DeepSec»)")
    for t in tdata_dirs:
        print(f"  {t}")
    trusted = parse_trusted(existing_env.get("TRUSTED_PROCESSES") or DEFAULT_TRUSTED)
    extra_signers = check_telegram_signatures(tdata_dirs, trusted, opts)

    print("2/6 Готовлю папку данных (доступ только SYSTEM и администраторам)…")
    canary_dir = data_dir / "canary"
    canary_dir.mkdir(parents=True, exist_ok=True)
    winacl.run_checked(["icacls", str(data_dir), "/inheritance:r", "/grant:r",
                        "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])

    print("3/6 Создаю ловушки…")
    ours = {d.lower() for d in split_list(existing_env.get("DECOY_DIRS"))}
    decoys = []
    for app in DECOY_APPS:
        root = Path(os.environ["APPDATA"]) / app
        decoy = root / "tdata"
        if root.exists() and str(decoy).lower() not in ours:
            # Папка есть, но создавали её не мы — это настоящий клиент, его tdata трогать нельзя.
            print(f"  пропускаю {root} — похоже, вы пользуетесь этим клиентом")
            continue
        if not (decoy / "key_datas").exists():
            create_decoy(decoy)
        decoys.append(decoy)
        print(f"  {decoy}")

    print("4/6 Включаю аудит Windows и правила аудита на файлах…")
    winacl.enable_audit_policy()
    for t in tdata_dirs:
        winacl.protect_tdata(t)
    for target in (*decoys, canary_dir):
        winacl.add_read_audit(target, recursive=True)
    (canary_dir / "selftest.bin").write_bytes(os.urandom(64))

    print("5/6 Настройки…")
    write_env(env_path, connection, tdata_dirs, decoys, extra_signers)
    state_path = data_dir / "state.json"
    if not state_path.exists():
        armed = _ask("Сразу включить авто-реакцию (убивать нарушителей)? Иначе — только уведомления", True, opts)
        state_path.write_text(json.dumps({"armed": armed}), "utf-8")

    print("6/6 Регистрирую задачу планировщика (запуск от SYSTEM при старте Windows)…")
    winacl.run_checked(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", _PS_REGISTER_TASK],
                       env={**os.environ, "DEEPSEC_EXE": exe, "DEEPSEC_ARGS": args, "DEEPSEC_WORKDIR": workdir,
                            "DEEPSEC_TASK": TASK_NAME})
    print(f"\n✅ Готово. Агент запущен; лог: {data_dir / 'agent.log'}.\n"
          "   В боте должен появиться компьютер — откройте его и нажмите «🧪 Самопроверка».")
    return 0


def uninstall() -> int:
    """Убирает всё, что сделал setup: задачу, правила брандмауэра, изоляцию, ловушки, папку данных.
    Политика аудита Windows остаётся — она безвредна, а её прежнее состояние неизвестно."""
    from . import response
    from .state import AgentState

    if not _is_admin():
        print("Запустите от имени администратора.")
        return 1
    for args in (("/End",), ("/Delete", "/F")):
        subprocess.run(["schtasks", *args, "/TN", TASK_NAME], capture_output=True, creationflags=NO_WINDOW)

    data_dir = Path(DEFAULT_DATA_DIR)
    state = AgentState.load(data_dir / "state.json")
    if state.isolated:
        try:
            response.unisolate()
            print("Сеть восстановлена")
        except response.ResponseError as e:
            print(f"⚠️  Не удалось снять изоляцию: {e}")
    for rule in state.blocked:
        try:
            response.unblock(rule)
        except response.ResponseError:
            pass

    for decoy in split_list(_load_env(data_dir / ".env").get("DECOY_DIRS")):
        # Ловушки создавал setup — вместе с папкой «клиента», если в ней больше ничего нет.
        shutil.rmtree(decoy, ignore_errors=True)
        try:
            Path(decoy).parent.rmdir()
        except OSError:
            pass
    shutil.rmtree(data_dir, ignore_errors=True)
    print("DeepSec удалён с этого компьютера.")
    return 0


def check() -> int:
    print("tdata:")
    tdata_dirs = find_tdata()
    for t in tdata_dirs:
        print(f"  {t}")
    env_path = Path(DEFAULT_DATA_DIR) / ".env"
    env = _load_env(env_path)
    print("Подписи Telegram.exe:")
    check_telegram_signatures(tdata_dirs, parse_trusted(env.get("TRUSTED_PROCESSES") or DEFAULT_TRUSTED), None)
    if env:
        print(f"Сервер: {env.get('SERVER_URL', '—')}")
        print(f"Ловушки: {', '.join(split_list(env.get('DECOY_DIRS'))) or 'нет'}")
    else:
        print(f"Нет {env_path} (или нет прав его прочитать) — setup ещё не выполнялся")
    return 0
