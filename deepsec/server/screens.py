"""Сборка экранов меню: данные + текст + клавиатура."""
from __future__ import annotations

from typing import TYPE_CHECKING

from aiogram.types import InlineKeyboardMarkup

from . import keyboards as kb
from . import texts

if TYPE_CHECKING:
    from .core import Server

Screen = tuple[str, InlineKeyboardMarkup]

# После действия показываем этот экран (цель — та же, что у действия).
AFTER = {
    "lock": "pc", "isolate": "pc", "unisolate": "pc", "arm": "pc", "disarm": "pc", "selftest": "pc",
    "unblock": "blocks", "unblock_all": "blocks",
    "kill": "inc", "block": "inc", "quarantine": "inc", "trust": "inc",
    "terminate": "home", "lockdown_off": "home",
    "sess_kill": "sessions", "sess_trust": "sess", "sess_untrust": "sess",
    "pet_on": "pet", "pet_off": "pet", "pet_say": "pet", "pet_text": "pet",
}
SCREENS = frozenset({"home", "pc", "blocks", "incidents", "inc", "sessions", "sess", "help",
                     "confirm_isolate", "confirm_terminate", "pet"})
# Экраны, для которых сервер ждёт ответа компьютера (несколько секунд).
SLOW_SCREENS = frozenset({"apps"})


async def build(server: Server, screen: str, target: str = "", notice: str = "") -> Screen:
    if screen == "pc":
        agent = server.hub.agents.get(target)
        return texts.pc(agent, notice), kb.pc(agent)
    if screen == "blocks":
        agent = server.hub.agents.get(target)
        return texts.blocks(agent, notice), kb.blocks(agent)
    if screen == "pet":
        agent = server.hub.agents.get(target)
        return texts.pet(agent, notice), kb.pet(agent)
    if screen == "apps":
        return texts.apps(target, await server.apps(target), notice), kb.apps(target)
    if screen == "incidents":
        items = server.journal.last(10)
        return texts.incidents(items, notice), kb.incidents(items)
    if screen == "inc":
        inc = server.journal.get(target)
        return texts.incident_screen(inc, notice), kb.incident(inc)
    if screen == "sessions":
        try:
            items = await server.list_sessions()
        except Exception as e:
            return texts.sessions_error(e), kb.only_back()
        trusted = server.state.trusted_sessions
        return texts.sessions(items, trusted, notice), kb.sessions(items, trusted)
    if screen == "sess":
        item = server.session_by_index(int(target or -1))
        trusted = server.state.trusted_sessions
        return texts.session(item, trusted, notice), kb.session(item, target, trusted)
    if screen == "help":
        return texts.HELP, kb.only_back()
    if screen == "confirm_isolate":
        return texts.confirm_isolate(target), kb.confirm("🌐 Да, отрезать от сети", "isolate", "pc", target)
    if screen == "confirm_terminate":
        return texts.confirm_terminate(), kb.confirm("📵 Да, завершить", "terminate", "home")
    return texts.home(server, notice), kb.home(server)


def code_prompt(action: str, error: str = "") -> Screen:
    return texts.code_prompt(action, error), kb.cancel()


def pet_prompt() -> Screen:
    return texts.pet_prompt(), kb.cancel()
