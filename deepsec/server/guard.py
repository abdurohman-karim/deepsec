"""Сторож аккаунта: отдельный сеанс Telegram (Telethon), которым агент сам завершает украденные сеансы.

Украденная копия tdata — это тот же сеанс, что и Telegram Desktop на ПК. Завершив его с другого сеанса,
мы делаем копию бесполезной, даже если стилер успел её отправить. Сеанс сторожа хранится в папке данных
агента, доступной только SYSTEM и администраторам.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Collection
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from telethon import TelegramClient, events, functions, types
from telethon.errors import FreshResetAuthorisationForbiddenError, RPCError, UnauthorizedError

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


async def interactive_login(session_path: Path, api_id: int, api_hash: str) -> str:
    """Вход сторожа из консоли: номер, код из Telegram, облачный пароль. Возвращает имя аккаунта."""
    client = make_client(session_path, api_id, api_hash)
    await client.start(phone=lambda: input("Номер телефона аккаунта (+7…): ").strip())
    me = await client.get_me()
    await client.disconnect()
    return f"{me.first_name or ''} {me.last_name or ''}".strip() or str(me.id)
