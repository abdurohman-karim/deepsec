from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from telethon import functions
from telethon.errors import AuthKeyUnregisteredError, FreshResetAuthorisationForbiddenError

from deepsec.server.guard import GuardRevoked, GuardTooFresh, SessionGuard

GUARD, DESKTOP, PHONE, THIEF = 1, 2, 3, 4


def auth(h: int, app: str, current: bool = False):
    return SimpleNamespace(hash=h, current=current, app_name=app, app_version="1.0", device_model="dev",
                           system_version="os", country="Russia", ip="1.2.3.4", date_created=None)


class FakeClient:
    def __init__(self, error: Exception | None = None):
        self.requests = []
        self.error = error

    def add_event_handler(self, *args) -> None:
        pass

    async def __call__(self, request):
        if isinstance(request, functions.account.GetAuthorizationsRequest):
            return SimpleNamespace(authorizations=[
                auth(GUARD, "DeepSec", current=True), auth(DESKTOP, "Telegram Desktop"),
                auth(PHONE, "Telegram iOS"), auth(THIEF, "Telegram Desktop"),
            ])
        if self.error:
            raise self.error
        self.requests.append(request)


async def noop(*args) -> None:
    pass


def test_terminates_everything_with_one_request_when_nothing_trusted():
    client = FakeClient()
    victims = asyncio.run(SessionGuard(client, noop).terminate_except(set()))
    assert [v.hash for v in victims] == [DESKTOP, PHONE, THIEF]
    assert [type(r) for r in client.requests] == [functions.auth.ResetAuthorizationsRequest]


def test_keeps_trusted_phone():
    client = FakeClient()
    victims = asyncio.run(SessionGuard(client, noop).terminate_except({PHONE}))
    assert [v.hash for v in victims] == [DESKTOP, THIEF]
    assert [r.hash for r in client.requests] == [DESKTOP, THIEF]
    assert all(isinstance(r, functions.account.ResetAuthorizationRequest) for r in client.requests)


@pytest.mark.parametrize("error, expected", [
    (FreshResetAuthorisationForbiddenError(request=None), GuardTooFresh),
    (AuthKeyUnregisteredError(request=None), GuardRevoked),
])
def test_errors_are_classified(error, expected):
    with pytest.raises(expected):
        asyncio.run(SessionGuard(FakeClient(error), noop).terminate_except(set()))


class LoginClient:
    """Имитирует Telegram: код сначала уходит в приложение, по повторному запросу — по SMS."""

    api_id, api_hash = 1, "h"

    def __init__(self, first_type, password_needed: bool = False):
        self.first_type = first_type
        self.password_needed = password_needed
        self.requests = []
        self.signed_in = []

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def is_user_authorized(self):
        return False

    async def __call__(self, request):
        self.requests.append(request)
        from telethon import types
        if isinstance(request, functions.auth.SendCodeRequest):
            return types.auth.SentCode(type=self.first_type, phone_code_hash="hash1",
                                       next_type=types.auth.CodeTypeSms(), timeout=60)
        return types.auth.SentCode(type=types.auth.SentCodeTypeSms(length=5), phone_code_hash="hash2")

    async def sign_in(self, phone=None, code=None, *, password=None, phone_code_hash=None):
        from telethon.errors import SessionPasswordNeededError
        self.signed_in.append((phone, code, password, phone_code_hash))
        if code and self.password_needed:
            raise SessionPasswordNeededError(request=None)

    async def get_me(self):
        return SimpleNamespace(first_name="Abdu", last_name=None, id=1)


def run_login(client, answers, secrets=()):
    from deepsec.server.guard import interactive_login

    said = []
    answers, secrets = iter(answers), iter(secrets)
    name = asyncio.run(interactive_login(None, 1, "h", ask=lambda _: next(answers), say=said.append,
                                         ask_secret=lambda _: next(secrets), client=client))
    return name, "\n".join(said)


def test_login_says_where_code_went_and_resends_by_sms():
    from telethon import types

    client = LoginClient(types.auth.SentCodeTypeApp(length=5), password_needed=True)
    name, said = run_login(client, ["+998 (90) 123-45-67", "", "12345"], secrets=["pass"])

    assert name == "Abdu"
    assert client.requests[0].phone_number == "+998901234567"
    assert "чат «Telegram» с синей галочкой" in said and "отправит его по SMS" in said
    assert isinstance(client.requests[1], functions.auth.ResendCodeRequest)
    assert client.signed_in == [("+998901234567", "12345", None, "hash2"), (None, None, "pass", None)]


def test_login_stops_when_email_setup_required():
    from telethon import types

    from deepsec.server.guard import GuardError

    with pytest.raises(GuardError, match="почту для входа"):
        run_login(LoginClient(types.auth.SentCodeTypeSetUpEmailRequired()), ["+998901234567"])


def test_normalize_phone():
    from deepsec.server.guard import normalize_phone

    assert normalize_phone(" +998 90 123-45-67 ") == "+998901234567"
    assert normalize_phone("abc") == ""
