"""Сторож аккаунта: отдельный сеанс Telegram (Telethon) на сервере, которым сервер сам завершает
украденные сеансы.

Украденная копия tdata — это тот же сеанс, что и Telegram Desktop на ПК. Завершив его с другого сеанса,
мы делаем копию бесполезной, даже если стилер успел её отправить.
"""
from __future__ import annotations

import asyncio
import getpass
import io
import logging
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from telethon import TelegramClient, events, functions, types
from telethon.errors import (
    FloodWaitError,
    FreshResetAuthorisationForbiddenError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberInvalidError,
    RPCError,
    SessionPasswordNeededError,
    UnauthorizedError,
)

from .. import __version__

log = logging.getLogger(__name__)

DEVICE_MODEL = "DeepSec Guard"


class GuardError(RuntimeError):
    pass


class GuardTooFresh(GuardError):
    """Telegram запрещает завершать чужие сеансы с сеанса, которому меньше 24 часов."""


class GuardRevoked(GuardError):
    """Сеанс сторожа завершён (например, «Завершить все другие сеансы» с телефона)."""


@dataclass(frozen=True)
class SessionInfo:
    hash: int
    current: bool
    app: str
    device: str
    place: str
    created: datetime | None

    def describe(self) -> str:
        return " · ".join(p for p in (self.app, self.device, self.place) if p)


def to_info(auth) -> SessionInfo:
    place = ", ".join(p for p in (getattr(auth, "country", ""), getattr(auth, "ip", "")) if p)
    return SessionInfo(
        hash=auth.hash,
        current=bool(getattr(auth, "current", False)),
        app=f"{getattr(auth, 'app_name', '')} {getattr(auth, 'app_version', '')}".strip(),
        device=f"{getattr(auth, 'device_model', '')} {getattr(auth, 'system_version', '')}".strip(),
        place=place,
        created=getattr(auth, "date_created", None),
    )


def make_client(session_path: Path, api_id: int, api_hash: str) -> TelegramClient:
    return TelegramClient(
        str(session_path), api_id, api_hash,
        device_model=DEVICE_MODEL, system_version="server", app_version=f"DeepSec {__version__}",
        connection_retries=-1, retry_delay=5,  # без сети — переподключаемся бесконечно
    )


class SessionGuard:
    def __init__(self, client, on_new_login: Callable[[int, str], Awaitable[None]]):
        self._client = client
        self._on_new_login = on_new_login
        # Telegram сам присылает событие о каждом новом входе в аккаунт — без опроса.
        client.add_event_handler(self._on_raw, events.Raw(types.UpdateNewAuthorization))

    async def start(self) -> None:
        await self._client.connect()
        if not await self._client.is_user_authorized():
            raise GuardRevoked("сторож не авторизован — выполните `python -m deepsec login`")

    async def run(self) -> None:
        await self._client.run_until_disconnected()

    async def close(self) -> None:
        await self._client.disconnect()

    async def _on_raw(self, update: types.UpdateNewAuthorization) -> None:
        description = " · ".join(p for p in (update.device, update.location) if p) or "неизвестное устройство"
        await self._on_new_login(update.hash, description)

    async def _call(self, request):
        try:
            return await self._client(request)
        except FreshResetAuthorisationForbiddenError as e:
            raise GuardTooFresh("сеансу сторожа меньше 24 часов — Telegram пока не даёт завершать сеансы") from e
        except UnauthorizedError as e:
            raise GuardRevoked("сеанс сторожа завершён — выполните `python -m deepsec login`") from e
        except RPCError as e:
            raise GuardError(str(e)) from e

    async def sessions(self) -> list[SessionInfo]:
        result = await self._call(functions.account.GetAuthorizationsRequest())
        return [to_info(a) for a in result.authorizations]

    async def terminate(self, session_hash: int) -> None:
        await self._call(functions.account.ResetAuthorizationRequest(hash=session_hash))

    async def terminate_except(self, keep: Collection[int]) -> list[SessionInfo]:
        """Завершает все сеансы, кроме сторожа и доверенных (`keep`). Возвращает завершённые."""
        sessions = await self.sessions()
        victims = [s for s in sessions if not s.current and s.hash not in keep]
        if not victims:
            return []
        if len(victims) == sum(not s.current for s in sessions):
            await self._call(functions.auth.ResetAuthorizationsRequest())  # одним запросом — быстрее
        else:
            for s in victims:
                await self.terminate(s.hash)
        return victims


def normalize_phone(raw: str) -> str:
    """'+998 (90) 123-45-67' -> '+998901234567'."""
    digits = "".join(c for c in raw if c.isdigit())
    return f"+{digits}" if digits else ""


def describe_sent_code(code_type) -> str:
    """Куда Telegram отправил код входа — без этого непонятно, где его искать."""
    t = types.auth
    if isinstance(code_type, t.SentCodeTypeApp):
        return ("в приложение Telegram: чат «Telegram» с синей галочкой на телефоне или в Telegram Desktop "
                "(не SMS)")
    if isinstance(code_type, (t.SentCodeTypeSms, t.SentCodeTypeFirebaseSms, t.SentCodeTypeSmsWord,
                              t.SentCodeTypeSmsPhrase)):
        return "по SMS"
    if isinstance(code_type, t.SentCodeTypeCall):
        return "звонком — робот продиктует код"
    if isinstance(code_type, t.SentCodeTypeFlashCall):
        return "сброшенным звонком — код это номер, с которого звонили"
    if isinstance(code_type, t.SentCodeTypeMissedCall):
        return f"пропущенным звонком — код это последние {code_type.length} цифр номера, с которого звонили"
    if isinstance(code_type, t.SentCodeTypeEmailCode):
        return f"на почту для входа {code_type.email_pattern}"
    if isinstance(code_type, t.SentCodeTypeFragmentSms):
        return f"через Fragment — номер куплен на fragment.com: {code_type.url}"
    return f"неизвестным способом ({type(code_type).__name__})"


def describe_next(next_type) -> str:
    t = types.auth
    if isinstance(next_type, t.CodeTypeSms):
        return "по SMS"
    if isinstance(next_type, (t.CodeTypeCall, t.CodeTypeFlashCall, t.CodeTypeMissedCall)):
        return "звонком"
    if isinstance(next_type, t.CodeTypeFragmentSms):
        return "через Fragment"
    return "другим способом"


async def interactive_login(
    session_path: Path,
    api_id: int,
    api_hash: str,
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
    ask_secret: Callable[[str], str] = getpass.getpass,
    client=None,
) -> str:
    """Вход сторожа из консоли. По умолчанию — QR-код, который сканирует телефон: код входа не нужен,
    а Telegram нередко не доставляет его сторонним приложениям с IP хостинга. Запасной путь — номер и код.
    Возвращает имя аккаунта."""
    client = client or make_client(session_path, api_id, api_hash)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            choice = ask("Как войти? 1 — QR-код с телефона (рекомендуется), 2 — номер и код [1]: ").strip()
            if choice == "2":
                await _sign_in(client, ask, say, ask_secret)
            else:
                await _qr_sign_in(client, say, ask_secret)
        me = await client.get_me()
    finally:
        await client.disconnect()
    return f"{me.first_name or ''} {me.last_name or ''}".strip() or str(me.id)


async def _sign_in(client, ask, say, ask_secret) -> None:
    while True:
        phone = normalize_phone(ask("Номер телефона в международном формате (например +998901234567): "))
        if not phone:
            continue
        say(f"Запрашиваю код для {phone}…")
        try:
            sent = await client(functions.auth.SendCodeRequest(phone, client.api_id, client.api_hash,
                                                               types.CodeSettings()))
            break
        except PhoneNumberInvalidError:
            say("⚠️  Telegram не знает такой номер — проверьте код страны и цифры.")
        except FloodWaitError as e:
            raise GuardError(f"Слишком много попыток входа — Telegram просит подождать {e.seconds // 60 + 1} мин.") from e

    if isinstance(sent, types.auth.SentCodePaymentRequired):
        raise GuardError("Telegram требует оплату за код входа для этого номера — войти через API сейчас нельзя.")
    if isinstance(sent.type, types.auth.SentCodeTypeSetUpEmailRequired):
        raise GuardError("Telegram требует сначала привязать почту для входа: на телефоне Настройки → "
                         "Конфиденциальность → Почта для входа. Потом повторите вход.")

    while True:
        say(f"📨 Код отправлен {describe_sent_code(sent.type)}.")
        if sent.next_type:
            say(f"   Не пришёл? Нажмите Enter без кода — Telegram отправит его {describe_next(sent.next_type)}"
                + (f" (можно через {sent.timeout} с)." if sent.timeout else "."))
        code = "".join(c for c in ask("Код: ") if c.isalnum())
        if not code:
            if not sent.next_type:
                say("   Другого способа Telegram не предлагает — подождите пару минут и проверьте ещё раз.")
                continue
            try:
                sent = await client(functions.auth.ResendCodeRequest(phone, sent.phone_code_hash))
            except PhoneCodeExpiredError:
                say("   Код истёк — запрашиваю новый.")
                sent = await client(functions.auth.SendCodeRequest(phone, client.api_id, client.api_hash,
                                                                   types.CodeSettings()))
            except FloodWaitError as e:
                say(f"   Telegram просит подождать {e.seconds} с перед повторной отправкой.")
            continue
        try:
            await client.sign_in(phone, code, phone_code_hash=sent.phone_code_hash)
            return
        except PhoneCodeInvalidError:
            say("⚠️  Неверный код, попробуйте ещё раз.")
        except PhoneCodeExpiredError:
            say("⚠️  Код истёк — запрашиваю новый.")
            sent = await client(functions.auth.SendCodeRequest(phone, client.api_id, client.api_hash,
                                                               types.CodeSettings()))
        except SessionPasswordNeededError:
            await _password(client, say, ask_secret)
            return


def render_qr(url: str) -> str:
    import qrcode

    qr = qrcode.QRCode(border=2)
    qr.add_data(url)
    out = io.StringIO()
    qr.print_ascii(out=out, invert=True)  # тёмные модули на светлом фоне — для тёмного терминала
    return out.getvalue()


async def _qr_sign_in(client, say, ask_secret) -> None:
    qr = await client.qr_login()
    say("На телефоне: Telegram → Настройки → Устройства → «Подключить устройство» и наведите камеру на QR-код.")
    while True:
        say(render_qr(qr.url))
        say("QR-код живёт около 30 секунд — если не успели, ниже появится новый.")
        try:
            await qr.wait()
            return
        except asyncio.TimeoutError:
            await qr.recreate()
        except SessionPasswordNeededError:
            await _password(client, say, ask_secret)
            return


async def _password(client, say, ask_secret) -> None:
    while True:
        try:
            await client.sign_in(password=ask_secret("Облачный пароль (2FA, символы не отображаются): "))
            return
        except PasswordHashInvalidError:
            say("⚠️  Неверный облачный пароль.")
