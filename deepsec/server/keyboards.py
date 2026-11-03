"""Inline-клавиатуры меню и уведомлений."""
from __future__ import annotations

import ntpath
from typing import TYPE_CHECKING

from aiogram.filters.callback_data import CallbackData
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from ..incidents import Incident, Kind, Severity
from ..protocol import PET_MOODS
from .texts import ICONS, PET_LABELS, local

if TYPE_CHECKING:
    from .core import Server
    from .guard import SessionInfo
    from .hub import AgentLink

FILE_KINDS = (Kind.TDATA_ACCESS, Kind.DECOY_ACCESS)
LOCK = "🔑"


class Btn(CallbackData, prefix="b"):
    """Кнопка меню. a — экран или действие, t — компьютер / инцидент / номер сеанса, r — правило брандмауэра."""
    a: str
    t: str = ""
    r: str = ""


class AlertBtn(CallbackData, prefix="al"):
    """Кнопка под уведомлением об инциденте."""
    a: str
    id: str


def _b(text: str, a: str, t: str = "", r: str = "") -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=Btn(a=a, t=t, r=r).pack())


def _al(text: str, a: str, inc: Incident) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=AlertBtn(a=a, id=inc.id).pack())


def _markup(*rows: list[InlineKeyboardButton] | None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[r for r in rows if r])


def _back(a: str = "home", t: str = "") -> list[InlineKeyboardButton]:
    return [_b("⬅️ Назад", a, t)]


# ---------- меню ----------

def home(server: Server) -> InlineKeyboardMarkup:
    agents = sorted(server.hub.agents.values(), key=lambda a: a.name)
    rows = [[_b(f"🖥 {a.name} {'🟢' if a.online else '🔴'}", "pc", a.name)] for a in agents]
    rows.append([_b("📋 Инциденты", "incidents"), _b("📱 Сеансы", "sessions")])
    rows.append([_b("📵 Завершить сеансы", "confirm_terminate")])
    if server.lockdown_active:
        rows.append([_b(f"🔓 Снять блокаду входов {LOCK}", "lockdown_off")])
    rows.append([_b("❓ Как это работает", "help"), _b("🔄 Обновить", "home")])
    return _markup(*rows)


def pc(agent: AgentLink | None) -> InlineKeyboardMarkup:
    if agent is None:
        return _markup(_back())
    name, st = agent.name, agent.status
    rows = []
    if agent.online:
        rows.append([_b("📸 Скриншот", "shot", name), _b("📋 Что запущено", "apps", name)])
        rows.append([_b("👁 Глаз на экране", "pet", name)])
        rows.append([_b("🔒 Заблокировать экран", "lock", name)])
        rows.append([_b(f"🌐 Вернуть сеть {LOCK}", "unisolate", name)] if st.get("isolated")
                    else [_b("🌐 Отрезать от сети", "confirm_isolate", name)])
        rows.append([_b(f"🟡 Только уведомления {LOCK}", "disarm", name)] if st.get("armed")
                    else [_b("🟢 Включить авто-реакцию", "arm", name)])
        rows.append([_b(f"🧱 Блокировки ({len(st.get('blocked') or {})})", "blocks", name),
                     _b("🧪 Самопроверка", "selftest", name)])
    rows.append([_b("🔄 Обновить", "pc", name), *_back()])
    return _markup(*rows)


def apps(name: str) -> InlineKeyboardMarkup:
    return _markup([_b("📸 Скриншот", "shot", name), _b("🔄 Обновить", "apps", name)], _back("pc", name))


def pet(agent: AgentLink | None) -> InlineKeyboardMarkup:
    if agent is None or not agent.online:
        return _markup(_back("pc", agent.name if agent else ""))
    name, current = agent.name, agent.status.get("pet") or ""
    moods = [_b(f"{'✅ ' if mood == current else ''}{PET_LABELS[mood]}", "pet_on", name, mood) for mood in PET_MOODS]
    rows = [moods[i:i + 2] for i in range(0, len(moods), 2)]
    rows.append([_b("✏️ Свой текст", "pet_text", name)])
    if current:
        rows.append([_b("🙈 Убрать с экрана", "pet_off", name)])
    rows.append([_b("🔄 Обновить", "pet", name), *_back("pc", name)])
    return _markup(*rows)


def blocks(agent: AgentLink | None) -> InlineKeyboardMarkup:
    if agent is None:
        return _markup(_back())
    blocked = agent.status.get("blocked") or {}
    rows = [[_b(f"🔓 {ntpath.basename(path)} {LOCK}", "unblock", agent.name, rule)] for rule, path in blocked.items()]
    if len(blocked) > 1:
        rows.append([_b(f"🔓 Снять все {LOCK}", "unblock_all", agent.name)])
    rows.append(_back("pc", agent.name))
    return _markup(*rows)


def incidents(items: list[Incident]) -> InlineKeyboardMarkup:
    rows = [[_b(f"{ICONS[i.severity]} {local(i.time):%d.%m %H:%M} {i.title[:32]}", "inc", i.id)]
            for i in reversed(items)]
    rows.append(_back())
    return _markup(*rows)


def incident(inc: Incident | None) -> InlineKeyboardMarkup:
    rows = []
    if inc is not None and inc.host:
        if inc.pid and inc.pid > 4:
            rows.append([_b("🔪 Убить процесс", "kill", inc.id)])
        if inc.process_path:
            rows.append([_b("🧱 Запретить сеть", "block", inc.id), _b("📦 В карантин", "quarantine", inc.id)])
            rows.append([_b(f"✅ Это моя программа {LOCK}", "trust", inc.id)])
    rows.append(_back("incidents"))
    return _markup(*rows)


def sessions(items: list[SessionInfo], trusted: dict[str, str]) -> InlineKeyboardMarkup:
    rows = []
    for i, s in enumerate(items):
        mark = "🛡" if s.current else ("⭐" if str(s.hash) in trusted else "📱")
        rows.append([_b(f"{mark} {s.describe()[:48]}", "sess", str(i))])
    rows.append([_b("📵 Завершить все, кроме ⭐", "confirm_terminate")])
    rows.append([_b("🔄 Обновить", "sessions"), *_back()])
    return _markup(*rows)


def session(item: SessionInfo | None, index: str, trusted: dict[str, str]) -> InlineKeyboardMarkup:
    rows = []
    if item is not None and not item.current:
        rows.append([_b("✖ Завершить этот сеанс", "sess_kill", index)])
        rows.append([_b("Убрать ⭐", "sess_untrust", index)] if str(item.hash) in trusted
                    else [_b(f"⭐ Доверять {LOCK}", "sess_trust", index)])
    rows.append(_back("sessions"))
    return _markup(*rows)


def confirm(yes_text: str, yes: str, no: str, t: str = "") -> InlineKeyboardMarkup:
    return _markup([_b(yes_text, yes, t)], [_b("↩️ Отмена", no, t)])


def cancel() -> InlineKeyboardMarkup:
    return _markup([_b("❌ Отмена", "cancel")])


def only_back(a: str = "home", t: str = "") -> InlineKeyboardMarkup:
    return _markup(_back(a, t))


# ---------- уведомления ----------

def alert(inc: Incident, confirm_action: str = "") -> InlineKeyboardMarkup | None:
    if confirm_action == "isolate":
        return _markup([_al("🌐 Да, отрезать от сети", "isolate_ok", inc)], [_al("↩️ Отмена", "back", inc)])
    if confirm_action == "terminate":
        return _markup([_al("📵 Да, завершить сеансы", "terminate_ok", inc)], [_al("↩️ Отмена", "back", inc)])

    if inc.kind == Kind.NEW_LOGIN:
        if inc.session is None or inc.actions:
            return None
        return _markup([_al("✖ Завершить этот сеанс", "login_kill", inc)])
    if inc.severity == Severity.INFO or not inc.host or inc.kind == Kind.AGENT_OFFLINE:
        return None

    rows = []
    if inc.kind in FILE_KINDS and not inc.actions_include("📵 Сеансы"):
        rows.append([_al("📵 Завершить сеансы", "terminate", inc)])
    process_row = []
    if inc.pid and inc.pid > 4:
        process_row.append(_al("🔪 Убить", "kill", inc))
    if inc.process_path:
        process_row += [_al("🧱 Без сети", "block", inc), _al("📦 Карантин", "quarantine", inc)]
    rows.append(process_row)
    rows.append([_al("🔒 Блок. экран", "lock", inc), _al("🌐 Отрезать сеть", "isolate", inc)])
    if inc.process_path:
        rows.append([_al(f"✅ Это моя программа {LOCK}", "trust", inc)])
    return _markup(*rows)
