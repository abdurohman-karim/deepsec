"""Включение аудита Windows: политика auditpol и SACL (правила аудита) на папках tdata, ловушках и canary."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .detector import AUDIT_POLICY_CHANGE_GUID, FILE_SYSTEM_GUID, LOGON_GUID

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
ACCOUNT_DIR_RE = re.compile(r"^[0-9A-F]{16}$")  # папки аккаунтов в tdata, например D877F783D5D3EF8C

# Аудит «Чтение данных» для Everyone (SID S-1-1-0 — не зависит от языка Windows).
# Через GetAccessControl('Audit') трогаем только SACL — без ошибок про владельца, как у Set-Acl.
_PS_ADD_AUDIT = r"""
$ErrorActionPreference = 'Stop'
$sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::ReadData,
    [System.Security.AccessControl.InheritanceFlags]$env:DEEPSEC_INHERIT,
    [System.Security.AccessControl.PropagationFlags]$env:DEEPSEC_PROPAGATE,
    [System.Security.AccessControl.AuditFlags]::Success)
$item = Get-Item -LiteralPath $env:DEEPSEC_TARGET -Force
$acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
$acl.AddAuditRule($rule)
$item.SetAccessControl($acl)
"""


def run_checked(args: list[str], env: dict[str, str] | None = None) -> None:
    result = subprocess.run(args, capture_output=True, text=True, encoding="oem", errors="replace",
                            env=env, creationflags=NO_WINDOW)
    if result.returncode != 0:
        raise RuntimeError(f"{args[0]}: {(result.stdout + result.stderr).strip()}")


def enable_audit_policy() -> None:
    # GUID вместо названий — названия подкатегорий переведены в русской Windows.
    for guid in (FILE_SYSTEM_GUID, LOGON_GUID, AUDIT_POLICY_CHANGE_GUID):
        run_checked(["auditpol", "/set", f"/subcategory:{guid}", "/success:enable", "/failure:enable"])
    # 200 МБ журнала Security, чтобы события не вытеснялись за пару часов.
    run_checked(["wevtutil", "sl", "Security", "/ms:209715200"])


def add_read_audit(target: Path, *, recursive: bool) -> None:
    """recursive=False — только файлы прямо в папке; True — файлы на любой глубине. Сами папки не аудируются,
    поэтому просмотр папки в Проводнике не вызывает тревогу — только чтение содержимого файлов."""
    env = {
        **os.environ,
        "DEEPSEC_TARGET": str(target),
        "DEEPSEC_INHERIT": "ObjectInherit",
        "DEEPSEC_PROPAGATE": "InheritOnly" if recursive else "InheritOnly, NoPropagateInherit",
    }
    run_checked(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", _PS_ADD_AUDIT], env=env)


def protect_tdata(tdata: Path) -> list[Path]:
    """Аудит key_datas и файлов в корне tdata + maps в папках аккаунтов. Кэш медиа (user_data) не трогаем —
    иначе журнал утонет в событиях от самого Telegram."""
    targets = [tdata, *(p for p in tdata.iterdir() if p.is_dir() and ACCOUNT_DIR_RE.match(p.name))]
    for target in targets:
        add_read_audit(target, recursive=False)
    return targets
