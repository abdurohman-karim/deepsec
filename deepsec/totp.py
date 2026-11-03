"""Второй фактор для опасных команд бота.

Если украдут сессию Telegram, вор сможет писать боту от вашего имени. Поэтому всё, что ОСЛАБЛЯЕТ защиту
(/disarm, /unisolate, /unblock, /trust), требует кода из приложения-аутентификатора на телефоне.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import pyotp

MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60


@dataclass(frozen=True)
class TotpResult:
    ok: bool
    message: str = ""
    locked_now: bool = False  # именно эта попытка исчерпала лимит — повод для тревоги


class TotpGuard:
    def __init__(self, secret: str, clock: Callable[[], float] = time.time):
        self._totp = pyotp.TOTP(secret)
        self._clock = clock
        self._failures = 0
        self._locked_until = 0.0
        self._last_code = ""

    def check(self, code: str) -> TotpResult:
        now = self._clock()
        if now < self._locked_until:
            return TotpResult(False, f"Слишком много неверных кодов. Подождите {int(self._locked_until - now) // 60 + 1} мин.")
        code = code.replace(" ", "")
        if code and code == self._last_code:
            return TotpResult(False, "Этот код уже использован — дождитесь следующего.")
        if code.isdigit() and self._totp.verify(code, for_time=now, valid_window=1):
            self._failures, self._last_code = 0, code
            return TotpResult(True)

        self._failures += 1
        if self._failures >= MAX_FAILURES:
            self._failures, self._locked_until = 0, now + LOCKOUT_SECONDS
            return TotpResult(False, "Неверный код. Команды с кодом заблокированы на 15 минут.", locked_now=True)
        return TotpResult(False, f"Неверный код (осталось попыток: {MAX_FAILURES - self._failures}).")
