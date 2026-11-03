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
