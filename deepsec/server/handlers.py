"""Обработчики: одна команда /menu, всё остальное — inline-кнопки. Бот отвечает только владельцу."""
from __future__ import annotations

from typing import TYPE_CHECKING

from aiogram import Bot, F, Router
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message

from . import keyboards as kb
from . import screens, texts, ui
from .keyboards import AlertBtn, Btn

if TYPE_CHECKING:
    from .core import Server

# Действия, ослабляющие защиту: только с кодом из аутентификатора.
CODE_ACTIONS = frozenset(texts.CODE_LABELS)


class Form(StatesGroup):
    code = State()


def _plain(notice: str) -> str:
    return notice.removeprefix("✅ ").removeprefix("⚠️ ")


def _after(action: str, target: str) -> tuple[str, str]:
    """Какой экран показать после действия (и после отмены ввода кода)."""
    return screens.AFTER.get(action, "home"), target


def build_router(owner_id: int) -> Router:
    router = Router(name="deepsec")
    owner = F.from_user.id == owner_id
    router.message.filter(owner, F.chat.type == "private")
    router.callback_query.filter(owner)

    @router.message(CommandStart())
    @router.message(Command("menu"))
    async def cmd_menu(message: Message, bot: Bot, server: Server, state: FSMContext) -> None:
        await state.clear()
        await ui.delete_incoming(message)
        text, markup = await screens.build(server, "home")
        await ui.send_fresh(bot, server, text, markup)

    @router.message(StateFilter(Form.code))
    async def on_code(message: Message, bot: Bot, server: Server, state: FSMContext) -> None:
        await ui.delete_incoming(message)  # код не остаётся в истории чата
        data = await state.get_data()
        action, target, extra = data.get("a", ""), data.get("t", ""), data.get("r", "")
        result = server.check_totp(message.text or "")
        if not result.ok:
            if result.locked_now:
                await state.clear()
                text, markup = await screens.build(server, "home", notice=f"⛔ {result.message}")
            else:
                text, markup = screens.code_prompt(action, result.message)
            await ui.show(bot, server, text, markup)
            return
        await state.clear()
        notice = await server.perform(action, target, extra)
        screen, screen_target = _after(action, target)
        text, markup = await screens.build(server, screen, screen_target, notice)
        await ui.show(bot, server, text, markup)

    @router.message()
    async def on_other(message: Message) -> None:
        await ui.delete_incoming(message)  # в чате остаётся только меню и уведомления

    @router.callback_query(Btn.filter())
    async def on_button(query: CallbackQuery, callback_data: Btn, bot: Bot, server: Server,
                        state: FSMContext) -> None:
        action, target, extra = callback_data.a, callback_data.t, callback_data.r
        message_id = query.message.message_id if query.message else None

        if action == "cancel":
            data = await state.get_data()
            await state.clear()
            screen, screen_target = _after(data.get("a", ""), data.get("t", ""))
            text, markup = await screens.build(server, screen, screen_target)
        elif action in CODE_ACTIONS:
            await state.set_state(Form.code)
            await state.update_data(a=action, t=target, r=extra)
            text, markup = screens.code_prompt(action)
        elif action in screens.SCREENS:
            await state.clear()
            text, markup = await screens.build(server, action, target)
        else:
            await query.answer("⏳")  # действие может занять несколько секунд
            notice = await server.perform(action, target, extra)
            screen, screen_target = _after(action, target)
            text, markup = await screens.build(server, screen, screen_target, notice)
            await ui.show(bot, server, text, markup, message_id)
            return
        await ui.show(bot, server, text, markup, message_id)
        await query.answer()

    @router.callback_query(AlertBtn.filter())
    async def on_alert(query: CallbackQuery, callback_data: AlertBtn, bot: Bot, server: Server,
                       state: FSMContext) -> None:
        inc = server.journal.get(callback_data.id)
        if inc is None:
            await query.answer("Инцидент не найден — возможно, журнал был очищен", show_alert=True)
            return
        action = callback_data.a

        if action in ("isolate", "terminate", "back"):
            await query.answer()
            await _edit_alert(query, inc, kb.alert(inc, "" if action == "back" else action), text_too=False)
            return
        if action == "trust":
            await state.set_state(Form.code)
            await state.update_data(a="trust", t=inc.id, r="")
            text, markup = screens.code_prompt("trust")
            await ui.send_fresh(bot, server, text, markup)
            await query.answer("Отправьте код подтверждения ниже 👇")
            return

        await query.answer("⏳")
        if action in ("kill", "block", "quarantine", "login_kill"):
            notice = await server.perform(action, inc.id)  # результат сам дописывается в инцидент
        elif action == "terminate_ok":
            notice = server.terminate_sessions()
            inc.actions.append(notice)
        else:  # lock, isolate_ok
            notice = await server.perform("lock" if action == "lock" else "isolate", inc.host)
            inc.actions.append(_plain(notice))
        if not await _edit_alert(query, inc, kb.alert(inc)):
            server.notifier.send(notice)

    return router


async def _edit_alert(query: CallbackQuery, inc, markup, text_too: bool = True) -> bool:
    """Обновляет уведомление: дописывает принятые меры и меняет кнопки."""
    message = query.message
    if message is None or not hasattr(message, "edit_text"):
        return False  # сообщение старше 48 часов — Telegram его уже не отдаёт
    try:
        if text_too:
            await message.edit_text(texts.incident(inc), reply_markup=markup)
        else:
            await message.edit_reply_markup(reply_markup=markup)
        return True
    except TelegramAPIError:
        return False
