"""Telegram-бот (aiogram 3): уведомления об инцидентах и управление агентом.

Бот отвечает только владельцу (OWNER_ID). Команды, ослабляющие защиту, требуют TOTP-код.
"""
from __future__ import annotations

import asyncio
import logging
import ntpath
from html import escape
from typing import TYPE_CHECKING

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramNetworkError, TelegramRetryAfter
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.filters.callback_data import CallbackData
from aiogram.types import BotCommand, CallbackQuery, InlineKeyboardMarkup, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder

from .incidents import Incident, Kind, Severity

if TYPE_CHECKING:
    from .agent import Agent

log = logging.getLogger(__name__)

ICONS = {Severity.INFO: "ℹ️", Severity.WARNING: "⚠️", Severity.CRITICAL: "🚨"}
MAX_FILES_SHOWN = 5
SESSION_THEFT_HINT = (
    "\n\n<b>Что сделать сейчас:</b> на телефоне Telegram → Настройки → Устройства → "
    "«Завершить все другие сеансы». Украденная копия tdata — это ваш же сеанс Desktop, "
    "поэтому он тоже завершится; потом войдите в Desktop заново."
)
COMMANDS = [
    BotCommand(command="status", description="Состояние защиты"),
    BotCommand(command="events", description="Последние инциденты"),
    BotCommand(command="lock", description="Заблокировать ПК / выкинуть RDP"),
    BotCommand(command="isolate", description="Отрезать ПК от сети"),
    BotCommand(command="arm", description="Включить авто-реакцию"),
    BotCommand(command="selftest", description="Проверить, что аудит работает"),
    BotCommand(command="help", description="Все команды"),
]
HELP = """<b>DeepSec</b> — защита сессий Telegram Desktop

/status — состояние защиты
/events — последние 10 инцидентов
/selftest — проверить, что Windows сообщает о чтении tdata
/lock — заблокировать экран и выкинуть RDP-сеансы
/isolate — отрезать ПК от сети (бот останется на связи)
/kill <code>PID</code> — завершить процесс
/arm — включить авто-реакцию (убивать и блокировать нарушителей)
/blocked — что заблокировано в брандмауэре

<b>С кодом из аутентификатора</b> (ослабляют защиту):
/disarm <code>КОД</code> — только уведомлять, без авто-реакции
/unisolate <code>КОД</code> — вернуть сеть
/unblock <code>ПРАВИЛО|all КОД</code> — снять блокировку брандмауэра
/trust <code>ID_ИНЦИДЕНТА КОД</code> — доверять этому exe (по SHA-256)"""


class Act(CallbackData, prefix="a"):
    action: str
    incident: str = "-"


def _short(path: str) -> str:
    return ntpath.basename(path) or path


def format_incident(inc: Incident) -> str:
    lines = [f"{ICONS[inc.severity]} <b>{escape(inc.title)}</b>"]
    if inc.process_path or inc.pid:
        process = escape(inc.process_path or "неизвестно")
        lines.append(f"Процесс: <code>{process}</code>" + (f" (PID {inc.pid})" if inc.pid else ""))
    if inc.files:
        shown = ", ".join(escape(_short(f)) for f in inc.files[:MAX_FILES_SHOWN])
        more = len(inc.files) - MAX_FILES_SHOWN
        lines.append(f"Файлы: <code>{shown}</code>" + (f" (+{more})" if more > 0 else ""))
    lines += [f"{escape(k)}: <code>{escape(v)}</code>" for k, v in inc.details.items()]
    if inc.actions:
        lines.append("\n<b>Принятые меры:</b>\n" + "\n".join(escape(a) for a in inc.actions))
    lines.append(f"\n🕒 {inc.time.astimezone():%d.%m.%Y %H:%M:%S} · <code>{inc.id}</code>")
    text = "\n".join(lines)
    if inc.kind in (Kind.TDATA_ACCESS, Kind.DECOY_ACCESS):
        text += SESSION_THEFT_HINT
    return text


def incident_keyboard(inc: Incident) -> InlineKeyboardMarkup | None:
    if inc.severity == Severity.INFO:
        return None
    kb = InlineKeyboardBuilder()
    if inc.pid and inc.pid > 4:
        kb.button(text="🔪 Убить процесс", callback_data=Act(action="kill", incident=inc.id))
    if inc.process_path:
        kb.button(text="🧱 Запретить сеть", callback_data=Act(action="block", incident=inc.id))
        kb.button(text="📦 В карантин", callback_data=Act(action="quarantine", incident=inc.id))
    kb.button(text="🔒 Заблокировать ПК", callback_data=Act(action="lock"))
    kb.button(text="🌐 Изолировать ПК", callback_data=Act(action="isolate"))
    kb.adjust(2)
    return kb.as_markup()


ISOLATE_QUESTION = "Отключить ПК от сети? Останется только связь агента с ботом."


def isolate_keyboard() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🌐 Да, отрезать от сети", callback_data=Act(action="isolate_ok"))
    return kb.as_markup()


class Notifier:
    """Очередь исходящих сообщений: если сети нет, уведомления не теряются, а уходят, когда она появится."""

    def __init__(self, bot: Bot, chat_id: int):
        self._bot = bot
        self._chat_id = chat_id
        self._queue: asyncio.Queue[tuple[str, InlineKeyboardMarkup | None, bool]] = asyncio.Queue()

    def send(self, text: str, markup: InlineKeyboardMarkup | None = None, silent: bool = False) -> None:
        self._queue.put_nowait((text, markup, silent))

    def incident(self, inc: Incident) -> None:
        self.send(format_incident(inc), incident_keyboard(inc), silent=inc.severity == Severity.INFO)

    async def run(self) -> None:
        while True:
            text, markup, silent = await self._queue.get()
            while True:
                try:
                    await self._bot.send_message(self._chat_id, text, reply_markup=markup, disable_notification=silent)
                    break
                except TelegramRetryAfter as e:
                    await asyncio.sleep(e.retry_after)
                except TelegramNetworkError:
                    await asyncio.sleep(5)
                except TelegramAPIError:
                    log.exception("Telegram отклонил сообщение")
                    break


def create_bot(token: str) -> Bot:
    return Bot(token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))


def build_dispatcher(agent: Agent) -> Dispatcher:
    router = Router()
    owner = F.from_user.id == agent.cfg.owner_id
    router.message.filter(owner)
    router.callback_query.filter(owner)

    async def check_code(message: Message, code: str) -> bool:
        try:
            await message.delete()  # не оставляем код в истории чата
        except TelegramAPIError:
            pass
        result = agent.check_totp(code)
        if not result.ok:
            await message.answer(f"⛔ {escape(result.message)}")
        return result.ok

    @router.message(CommandStart())
    @router.message(Command("help"))
    async def cmd_help(message: Message) -> None:
        await message.answer(HELP)

    @router.message(Command("status"))
    async def cmd_status(message: Message) -> None:
        await message.answer(agent.status_text())

    @router.message(Command("events"))
    async def cmd_events(message: Message) -> None:
        items = agent.journal.last(10)
        if not items:
            await message.answer("Инцидентов пока не было ✨")
            return
        lines = [
            f"{ICONS[i.severity]} <code>{i.id}</code> {i.time.astimezone():%d.%m %H:%M} — {escape(i.title)}"
            + (f" (<code>{escape(_short(i.process_path))}</code>)" if i.process_path else "")
            for i in reversed(items)
        ]
        await message.answer("\n".join(lines))

    @router.message(Command("selftest"))
    async def cmd_selftest(message: Message) -> None:
        await message.answer("⏳ Читаю canary-файл и жду событие из журнала…")
        ok = await agent.run_selftest()
        await message.answer("✅ Аудит работает" if ok else "❌ Событие не пришло — аудит не работает, см. README")

    @router.message(Command("lock"))
    async def cmd_lock(message: Message) -> None:
        await message.answer(escape(await agent.act_lock()))

    @router.message(Command("isolate"))
    async def cmd_isolate(message: Message) -> None:
        await message.answer(ISOLATE_QUESTION, reply_markup=isolate_keyboard())

    @router.message(Command("kill"))
    async def cmd_kill(message: Message, command: CommandObject) -> None:
        if not command.args or not command.args.strip().isdigit():
            await message.answer("Использование: /kill <code>PID</code>")
            return
        await message.answer(escape(await agent.act_kill(int(command.args), None)))

    @router.message(Command("arm"))
    async def cmd_arm(message: Message) -> None:
        agent.set_armed(True)
        await message.answer("🟢 Авто-реакция включена")

    @router.message(Command("blocked"))
    async def cmd_blocked(message: Message) -> None:
        if not agent.state.blocked:
            await message.answer("В брандмауэре ничего не заблокировано")
            return
        lines = [f"<code>{escape(name)}</code> — {escape(path)}" for name, path in agent.state.blocked.items()]
        await message.answer("🧱 Заблокированы:\n" + "\n".join(lines))

    @router.message(Command("disarm"))
    async def cmd_disarm(message: Message, command: CommandObject) -> None:
        if await check_code(message, command.args or ""):
            agent.set_armed(False)
            await message.answer("🟡 Авто-реакция выключена — только уведомления. Вернуть: /arm")

    @router.message(Command("unisolate"))
    async def cmd_unisolate(message: Message, command: CommandObject) -> None:
        if await check_code(message, command.args or ""):
            await message.answer(escape(await agent.act_unisolate()))

    @router.message(Command("unblock"))
    async def cmd_unblock(message: Message, command: CommandObject) -> None:
        parts = (command.args or "").split()
        if len(parts) != 2:
            await message.answer("Использование: /unblock <code>ПРАВИЛО|all КОД</code>")
            return
        if await check_code(message, parts[1]):
            names = list(agent.state.blocked) if parts[0] == "all" else [parts[0]]
            results = [await agent.act_unblock(name) for name in names]
            await message.answer(escape("\n".join(results) or "Нечего разблокировать"))

    @router.message(Command("trust"))
    async def cmd_trust(message: Message, command: CommandObject) -> None:
        parts = (command.args or "").split()
        if len(parts) != 2:
            await message.answer("Использование: /trust <code>ID_ИНЦИДЕНТА КОД</code>")
            return
        inc = agent.journal.get(parts[0])
        if inc is None or not inc.process_path:
            await message.answer("Инцидент не найден или в нём нет пути к exe")
            return
        if await check_code(message, parts[1]):
            await message.answer(escape(await agent.trust_process(inc.process_path)))

    @router.callback_query(Act.filter())
    async def on_action(query: CallbackQuery, callback_data: Act) -> None:
        await query.answer()
        inc = agent.journal.get(callback_data.incident) if callback_data.incident != "-" else None
        match callback_data.action:
            case "kill" if inc and inc.pid:
                result = await agent.act_kill(inc.pid, inc.process_path)
            case "block" if inc and inc.process_path:
                result = await agent.act_block(inc.process_path)
            case "quarantine" if inc and inc.process_path:
                result = await agent.act_quarantine(inc.process_path)
            case "lock":
                result = await agent.act_lock()
            case "isolate":
                agent.notifier.send(ISOLATE_QUESTION, isolate_keyboard())
                return
            case "isolate_ok":
                result = await agent.act_isolate()
            case _:
                result = "Инцидент не найден — возможно, журнал был очищен"
        # Отвечаем через очередь, а не query.message: у старых сообщений он может быть недоступен.
        agent.notifier.send(escape(result))

    dp = Dispatcher()
    dp.include_router(router)
    return dp


async def set_commands(bot: Bot) -> None:
    try:
        await bot.set_my_commands(COMMANDS)
    except TelegramAPIError:
        log.warning("Не удалось установить меню команд")
