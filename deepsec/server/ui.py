"""Чистый чат.

У владельца одно «живое» сообщение меню (state.menu_msg_id). Все экраны показываются его редактированием;
новое отправляется только когда без этого нельзя (/menu, старое удалено) — и тогда прежнее удаляется.
Сообщения владельца (коды подтверждения, случайный текст) бот удаляет сразу.
Уведомления об инцидентах — отдельные сообщения: они должны звенеть и оставаться в истории.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest, TelegramNetworkError, TelegramRetryAfter
from aiogram.types import InlineKeyboardMarkup, Message

from ..incidents import Incident, Severity
from . import keyboards as kb
from . import texts

if TYPE_CHECKING:
    from .core import Server

log = logging.getLogger(__name__)


async def delete_message(bot: Bot, chat_id: int, message_id: int | None) -> None:
    if not message_id:
        return
    try:
        await bot.delete_message(chat_id, message_id)
        return
    except TelegramAPIError:
        pass
    # Сообщения старше 48 часов Telegram удалить не даёт — хотя бы убираем с них кнопки
    try:
        await bot.edit_message_reply_markup(chat_id=chat_id, message_id=message_id, reply_markup=None)
    except TelegramAPIError:
        pass


async def delete_incoming(message: Message) -> None:
    try:
        await message.delete()
    except TelegramAPIError:
        pass


async def _edit(bot: Bot, chat_id: int, message_id: int, text: str, markup: InlineKeyboardMarkup | None) -> bool:
    try:
        await bot.edit_message_text(text=text, chat_id=chat_id, message_id=message_id, reply_markup=markup)
        return True
    except TelegramBadRequest as e:
        return "message is not modified" in e.message


async def show(bot: Bot, server: Server, text: str, markup: InlineKeyboardMarkup | None,
               message_id: int | None = None) -> None:
    """Показать экран в живом сообщении. message_id — сообщение, на котором нажали кнопку."""
    chat_id, live = server.cfg.owner_id, server.state.menu_msg_id
    target = message_id or live
    if target and await _edit(bot, chat_id, target, text, markup):
        if target != live:
            # Нажали кнопку на другом (старом) меню — теперь живое оно, прежнее убираем
            await delete_message(bot, chat_id, live)
            server.state.menu_msg_id = target
            server.state.save()
        return
    await send_fresh(bot, server, text, markup)


async def send_fresh(bot: Bot, server: Server, text: str, markup: InlineKeyboardMarkup | None) -> None:
    """Новое живое сообщение внизу чата; старое удаляется."""
    sent = await bot.send_message(server.cfg.owner_id, text, reply_markup=markup)
    await delete_message(bot, server.cfg.owner_id, server.state.menu_msg_id)
    server.state.menu_msg_id = sent.message_id
    server.state.save()


class TelegramNotifier:
    """Очередь уведомлений: если Telegram недоступен, они не теряются, а уходят, когда связь появится."""

    def __init__(self, bot: Bot, chat_id: int):
        self._bot = bot
        self._chat_id = chat_id
        self._queue: asyncio.Queue[tuple[str, InlineKeyboardMarkup | None, bool]] = asyncio.Queue()

    def send(self, text: str, markup: InlineKeyboardMarkup | None = None, silent: bool = False) -> None:
        self._queue.put_nowait((text, markup, silent))

    def incident(self, inc: Incident) -> None:
        self.send(texts.incident(inc), kb.alert(inc), silent=inc.severity == Severity.INFO)

    async def run(self) -> None:
        while True:
            text, markup, silent = await self._queue.get()
            while True:
                try:
                    await self._bot.send_message(self._chat_id, text, reply_markup=markup,
                                                 disable_notification=silent)
                    break
                except TelegramRetryAfter as e:
                    await asyncio.sleep(e.retry_after)
                except TelegramNetworkError:
                    await asyncio.sleep(5)
                except TelegramAPIError:
                    log.exception("Telegram отклонил сообщение")
                    break
