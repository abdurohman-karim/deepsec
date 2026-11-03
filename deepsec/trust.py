"""Проверка, можно ли доверять процессу: имя exe + валидная подпись нужного издателя или закреплённый SHA-256."""
from __future__ import annotations

import asyncio
import hashlib
import json
import ntpath
import os
import re
import subprocess
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass

_SUBJECT_RE = re.compile(r'\s*([A-Za-z0-9.]+)\s*=\s*("(?:[^"]|"")*"|[^,]*)\s*(?:,|$)')
_PS_SIGNATURE = (
    "$s = Get-AuthenticodeSignature -LiteralPath $env:DEEPSEC_TARGET; "
    "[pscustomobject]@{Status=[string]$s.Status; Subject=[string]$s.SignerCertificate.Subject} "
    "| ConvertTo-Json -Compress"
)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass(frozen=True)
class Signature:
    status: str  # Valid, NotSigned, HashMismatch, ...
    subject: str


def parse_subject(subject: str) -> dict[str, str]:
    """'CN=Telegram FZ-LLC, O="Foo, Inc.", C=AE' -> {'CN': 'Telegram FZ-LLC', 'O': 'Foo, Inc.', 'C': 'AE'}"""
    parts: dict[str, str] = {}
    for match in _SUBJECT_RE.finditer(subject):
        key, value = match.group(1).upper(), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1].replace('""', '"')
        parts.setdefault(key, value)
    return parts


def signer_matches(subject: str, allowed: Collection[str]) -> bool:
    parts = parse_subject(subject)
    return parts.get("O") in allowed or parts.get("CN") in allowed


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


async def read_signature(path: str) -> Signature:
    proc = await asyncio.create_subprocess_exec(
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_SIGNATURE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env={**os.environ, "DEEPSEC_TARGET": path},  # путь через env — без экранирования и инъекций
        creationflags=NO_WINDOW,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        data = json.loads(out.decode("utf-8", "replace") or "{}")
    except (asyncio.TimeoutError, json.JSONDecodeError):
        if proc.returncode is None:
            proc.kill()
        return Signature("Error", "")
    return Signature(str(data.get("Status") or ""), str(data.get("Subject") or ""))


class TrustChecker:
    def __init__(
        self,
        trusted: dict[str, frozenset[str]],
        pinned_hashes: Callable[[], Collection[str]] = lambda: (),
        signature_reader: Callable[[str], Awaitable[Signature]] = read_signature,
    ):
        self._trusted = trusted
        self._pinned = pinned_hashes
        self._read_signature = signature_reader
        self._cache: dict[tuple[str, int, int], bool] = {}

    def invalidate(self) -> None:
        self._cache.clear()

    async def __call__(self, path: str) -> bool:
        if not path:
            return False
        allowed = self._trusted.get(ntpath.basename(path).lower())
        pinned = self._pinned()
        # Самый частый случай для стилера: имени нет в белом списке — решаем мгновенно, без PowerShell.
        if not allowed and not pinned:
            return False
        try:
            st = os.stat(path)
        except OSError:
            return False
        key = (path.lower(), st.st_mtime_ns, st.st_size)
        if (cached := self._cache.get(key)) is not None:
            return cached

        ok = False
        if allowed:
            sig = await self._read_signature(path)
            ok = sig.status == "Valid" and signer_matches(sig.subject, allowed)
        if not ok and pinned:
            ok = await asyncio.to_thread(sha256_file, path) in pinned
        self._cache[key] = ok
        return ok
