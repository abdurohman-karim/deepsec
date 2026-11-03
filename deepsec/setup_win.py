"""Установка на Windows. Запускать из PowerShell «от имени администратора»: python -m deepsec setup"""
from __future__ import annotations

import asyncio
import ctypes
import json
import os
import platform
import sys
from pathlib import Path

import psutil
from dotenv import dotenv_values

from . import winacl
from .config import DEFAULT_DATA_DIR, DEFAULT_TRUSTED, PROJECT_DIR, parse_trusted, split_list
from .protocol import AGENT_PATH, normalize_fingerprint
from .trust import parse_subject, read_signature, signer_matches

TASK_NAME = "DeepSec Agent"
# Форки Telegram, которые ищут стилеры. Если вы ими не пользуетесь — любое чтение их tdata стопроцентно чужое.
DECOY_APPS = ("AyuGram Desktop", "Kotatogram Desktop", "64Gram Desktop")

_PS_REGISTER_TASK = r"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute $env:DEEPSEC_PYTHON -Argument '-m deepsec run' -WorkingDirectory $env:DEEPSEC_WORKDIR
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $env:DEEPSEC_TASK -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $env:DEEPSEC_TASK
"""


def _ask(prompt: str, default: bool) -> bool:
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not answer else answer in {"y", "yes", "д", "да"}


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


def check_telegram_signatures(tdata_dirs: list[Path], trusted: dict[str, frozenset[str]]) -> list[str]:
    """Проверяем, что ваш Telegram.exe подписан тем, кому мы доверяем, — иначе агент убьёт сам Telegram."""
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
            if org and _ask(f"  Издатель «{org}» не в списке доверенных. Добавить?", True):
                extra_signers.append(org)
    return extra_signers


def write_env(path: Path, existing: dict[str, str], tdata_dirs: list[Path], decoy_dirs: list[Path],
              extra_signers: list[str]) -> dict[str, str]:
    env = dict(existing)
    if not env.get("SERVER_URL"):
        print("\nДанные сервера показал ./deploy.sh при первой выкладке (их же можно посмотреть в .env на сервере).")
        host = input("Адрес сервера (IP или домен): ").strip()
        port = input("Порт агентов [8443]: ").strip() or "8443"
        env["SERVER_URL"] = f"wss://{host}:{port}{AGENT_PATH}"
    if not env.get("SERVER_FINGERPRINT"):
        env["SERVER_FINGERPRINT"] = normalize_fingerprint(input("SHA-256 отпечаток сертификата сервера: "))
    if not env.get("AGENT_TOKEN"):
        env["AGENT_TOKEN"] = input("AGENT_TOKEN: ").strip()
    env.setdefault("AGENT_NAME", platform.node())
    env["TDATA_DIRS"] = ";".join(str(p) for p in tdata_dirs)
    env["DECOY_DIRS"] = ";".join(str(p) for p in decoy_dirs)
    if extra_signers:
        trusted = parse_trusted(env.get("TRUSTED_PROCESSES") or DEFAULT_TRUSTED)
        for name in ("telegram.exe", "updater.exe"):
            trusted[name] = trusted.get(name, frozenset()) | set(extra_signers)
        env["TRUSTED_PROCESSES"] = ";".join(f"{n}={'|'.join(sorted(s))}" for n, s in trusted.items())
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), "utf-8")
    return env


def setup() -> int:
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Запустите от имени администратора.")
        return 1

    python = Path(sys.executable)
    if python.with_name("pythonw.exe").exists():
        python = python.with_name("pythonw.exe")  # без консольного окна
    if str(PROJECT_DIR).lower().startswith(str(Path(os.environ["USERPROFILE"])).lower()) or \
            str(python).lower().startswith(str(Path(os.environ["USERPROFILE"])).lower()):
        print("⚠️  Код или Python лежат в папке пользователя. Агент работает от SYSTEM, поэтому вирус без прав\n"
              "   администратора сможет подменить его код и получить SYSTEM. Рекомендуется C:\\Program Files\\DeepSec.")
        if not _ask("Продолжить всё равно?", False):
            return 1

    print("1/6 Ищу tdata…")
    tdata_dirs = find_tdata()
    if not tdata_dirs:
        print("  tdata не найдена. Запустите Telegram Desktop и повторите.")
        return 1
    for t in tdata_dirs:
        print(f"  {t}")
    env_path = Path(DEFAULT_DATA_DIR) / ".env"
    existing_env = {k: v for k, v in dotenv_values(env_path).items() if v} if env_path.exists() else {}
    trusted = parse_trusted(existing_env.get("TRUSTED_PROCESSES") or DEFAULT_TRUSTED)
    extra_signers = check_telegram_signatures(tdata_dirs, trusted)

    print("2/6 Готовлю папку данных (доступ только SYSTEM и администраторам)…")
    data_dir = Path(DEFAULT_DATA_DIR)
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
    write_env(env_path, existing_env, tdata_dirs, decoys, extra_signers)
    state_path = data_dir / "state.json"
    if not state_path.exists():
        armed = _ask("Сразу включить авто-реакцию (убивать нарушителей)? Иначе — только уведомления", True)
        state_path.write_text(json.dumps({"armed": armed}), "utf-8")

    print("6/6 Регистрирую задачу планировщика (запуск от SYSTEM при старте Windows)…")
    winacl.run_checked(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", _PS_REGISTER_TASK],
                       env={**os.environ, "DEEPSEC_PYTHON": str(python), "DEEPSEC_WORKDIR": str(PROJECT_DIR),
                            "DEEPSEC_TASK": TASK_NAME})
    print(f"\n✅ Готово. Агент запущен; лог: {data_dir / 'agent.log'}.\n"
          "   В боте должен появиться компьютер — откройте его и нажмите «🧪 Самопроверка».")
    return 0


def check() -> int:
    print("tdata:")
    tdata_dirs = find_tdata()
    for t in tdata_dirs:
        print(f"  {t}")
    env_path = Path(DEFAULT_DATA_DIR) / ".env"
    trusted_spec = (dotenv_values(env_path).get("TRUSTED_PROCESSES") if env_path.exists() else None)
    print("Подписи Telegram.exe:")
    check_telegram_signatures(tdata_dirs, parse_trusted(trusted_spec or DEFAULT_TRUSTED))
    if env_path.exists():
        decoys = split_list(dotenv_values(env_path).get("DECOY_DIRS"))
        print(f"Ловушки: {', '.join(decoys) or 'нет'}")
    else:
        print(f"Нет {env_path} — setup ещё не выполнялся")
    return 0
