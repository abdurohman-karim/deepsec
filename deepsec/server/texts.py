"""Тексты экранов и уведомлений (HTML)."""
from __future__ import annotations

import ntpath
import time
from datetime import datetime, timezone, tzinfo
from html import escape
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo

from ..incidents import Incident, Kind, Severity

if TYPE_CHECKING:
    from .core import Server
    from .guard import SessionInfo
    from .hub import AgentLink

ICONS = {Severity.INFO: "ℹ️", Severity.WARNING: "⚠️", Severity.CRITICAL: "🚨"}
MAX_FILES_SHOWN = 5
SESSION_THEFT_HINT = (
    "\n\n<b>Что сделать сейчас:</b> нажмите «📵 Завершить сеансы» — украденная копия tdata это ваш же сеанс "
    "Desktop, поэтому он тоже завершится. Затем найдите и удалите вирус."
)
AUTO_TERMINATION_HINT = (
    "\n\nСеансы аккаунта завершаются автоматически (кроме доверенных) — итог придёт отдельным сообщением."
)
CODE_LABELS = {
    "disarm": "выключить авто-реакцию",
    "unisolate": "вернуть компьютеру сеть",
    "unblock": "снять блокировку в брандмауэре",
    "unblock_all": "снять все блокировки",
    "trust": "доверять этой программе",
    "sess_trust": "сделать сеанс доверенным",
    "lockdown_off": "снять блокаду входов",
}

_zone: tzinfo = timezone.utc


def set_timezone(name: str) -> None:
    global _zone
    try:
        _zone = ZoneInfo(name)
    except Exception:
        _zone = timezone.utc


def local(value: datetime | float) -> datetime:
    if not isinstance(value, datetime):
        value = datetime.fromtimestamp(value, timezone.utc)
    return value.astimezone(_zone)


def _short(path: str) -> str:
    return ntpath.basename(path) or path


def _with_notice(text: str, notice: str) -> str:
    return f"{escape(notice)}\n\n{text}" if notice else text


def _duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} мин"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} ч {minutes} мин" if hours < 48 else f"{hours // 24} дн"


# ---------- уведомления ----------

def incident(inc: Incident) -> str:
    lines = [f"{ICONS[inc.severity]} <b>{escape(inc.title)}</b>"]
    if inc.host:
        lines.append(f"🖥 {escape(inc.host)}")
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
    lines.append(f"\n🕒 {local(inc.time):%d.%m.%Y %H:%M:%S} · <code>{inc.id}</code>")
    text = "\n".join(lines)
    if any(a.startswith("📵 Сеансы: завершаю") for a in inc.actions):
        text += AUTO_TERMINATION_HINT
    elif inc.kind in (Kind.TDATA_ACCESS, Kind.DECOY_ACCESS):
        text += SESSION_THEFT_HINT
    return text


def terminated(victims: list[SessionInfo], lockdown_hours: float) -> str:
    lines = [f"📵 <b>Сеансы аккаунта завершены автоматически</b> ({len(victims)})"]
    lines += [f"• {escape(v.describe())}" for v in victims] or ["Других сеансов не было."]
    lines.append(
        f"\nУкраденная копия tdata больше не работает.\n🔒 <b>Блокада на {lockdown_hours:g} ч:</b> любой новый вход "
        "в аккаунт будет сразу завершён. Когда удалите вирус и будете готовы войти в Telegram Desktop заново — "
        "/menu → «🔓 Снять блокаду»."
    )
    return "\n".join(lines)


# ---------- экраны меню ----------

def _agent_line(agent: AgentLink) -> str:
    st = agent.status
    if not agent.online:
        seen = f" с {local(agent.last_seen):%d.%m %H:%M}" if agent.last_seen else ""
        return f"🖥 <b>{escape(agent.name)}</b> — 🔴 не на связи{seen}"
    mode = "🟢 защита" if st.get("armed") else "🟡 только уведомления"
    audit = {True: "аудит ✅", False: "аудит ❌"}.get(st.get("audit_ok"), "аудит ⏳")
    isolated = " · 🌐 изолирован" if st.get("isolated") else ""
    return f"🖥 <b>{escape(agent.name)}</b> — 🟢 на связи · {mode} · {audit}{isolated}"


def home(server: Server, notice: str = "") -> str:
    lines = ["🛡 <b>DeepSec</b>", ""]
    agents = sorted(server.hub.agents.values(), key=lambda a: a.name)
    lines += [_agent_line(a) for a in agents] or ["Компьютеров пока нет — установите агента на Windows (см. README)."]
    lines.append("")
    guard = "✅ на связи" if server.guard else f"❌ {escape(server.guard_problem)}"
    lines.append(f"📵 Сторож аккаунта: {guard}")
    if server.state.trusted_sessions:
        lines.append(f"⭐ Доверенных сеансов: {len(server.state.trusted_sessions)}")
    if server.state.pending_terminate:
        lines.append("⏳ Ожидает завершения сеансов — нет связи со сторожем")
    if server.lockdown_active:
        lines.append(f"🔒 Блокада новых входов до {local(server.state.lockdown_until):%d.%m %H:%M}")
    last = server.journal.last(1)
    if last:
        inc = last[0]
        lines.append(f"\nПоследнее: {ICONS[inc.severity]} {local(inc.time):%d.%m %H:%M} — {escape(inc.title)}")
    return _with_notice("\n".join(lines), notice)


def pc(agent: AgentLink | None, notice: str = "") -> str:
    if agent is None:
        return _with_notice("Компьютер не найден.", notice)
    st = agent.status
    lines = [f"🖥 <b>{escape(agent.name)}</b>"]
    if agent.online:
        started = st.get("started")
        uptime = ""
        if started:
            uptime = f", работает {_duration(time.time() - datetime.fromisoformat(started).timestamp())}"
        lines.append(f"🟢 на связи · агент {escape(str(st.get('version', '?')))}{uptime}")
    else:
        seen = f" с {local(agent.last_seen):%d.%m %H:%M}" if agent.last_seen else ""
        lines.append(f"🔴 не на связи{seen}")
        if st:
            lines.append("<i>Ниже — последние известные данные.</i>")
    if st:
        audit = {True: "✅ работает", False: "❌ НЕ работает"}.get(st.get("audit_ok"), "⏳ проверяется")
        lines += [
            "",
            f"Режим: {'🟢 авто-реакция (убивать и блокировать)' if st.get('armed') else '🟡 только уведомления'}",
            f"Аудит чтения tdata: {audit}",
            f"Изоляция сети: {'🔴 включена' if st.get('isolated') else 'выключена'}",
            f"Защищаемые tdata: {st.get('tdata', 0)} · ловушки: {st.get('decoys', 0)}",
            f"Блокировок: {len(st.get('blocked') or {})} · доверенных программ: {st.get('trusted_exes', 0)}",
        ]
    return _with_notice("\n".join(lines), notice)


def blocks(agent: AgentLink | None, notice: str = "") -> str:
    blocked = (agent.status.get("blocked") if agent else None) or {}
    if not blocked:
        return _with_notice("🧱 В брандмауэре ничего не заблокировано.", notice)
    lines = ["🧱 <b>Запрещена сеть</b>", ""]
    lines += [f"• <code>{escape(path)}</code>" for path in blocked.values()]
    lines.append("\nСнять блокировку можно только с кодом подтверждения 🔑.")
    return _with_notice("\n".join(lines), notice)


def incidents(items: list[Incident], notice: str = "") -> str:
    text = "📋 <b>Последние инциденты</b>" if items else "📋 Инцидентов пока не было ✨"
    return _with_notice(text, notice)


def incident_screen(inc: Incident | None, notice: str = "") -> str:
    return _with_notice(incident(inc) if inc else "Инцидент не найден.", notice)


def sessions(items: list[SessionInfo], trusted: dict[str, str], notice: str = "") -> str:
    lines = ["📱 <b>Сеансы аккаунта Telegram</b>", ""]
    for s in items:
        mark = "🛡" if s.current else ("⭐" if str(s.hash) in trusted else "•")
        lines.append(f"{mark} {escape(s.describe())}" + (" — сторож DeepSec" if s.current else ""))
    lines.append("\n⭐ — доверенные: при краже tdata они не завершаются. Отметьте так свой телефон.")
    return _with_notice("\n".join(lines), notice)


def session(item: SessionInfo | None, trusted: dict[str, str], notice: str = "") -> str:
    if item is None:
        return _with_notice("Список сеансов устарел — откройте его заново.", notice)
    lines = [f"📱 <b>{escape(item.app or 'Сеанс')}</b>", escape(item.device), escape(item.place)]
    if item.created:
        lines.append(f"Вход: {local(item.created):%d.%m.%Y %H:%M}")
    if item.current:
        lines.append("\n🛡 Это сторож DeepSec — его не завершайте.")
    elif str(item.hash) in trusted:
        lines.append("\n⭐ Доверенный — при краже tdata не завершается.")
    return _with_notice("\n".join(l for l in lines if l), notice)


def sessions_error(error: Exception) -> str:
    return f"📱 Не удалось получить сеансы: {escape(str(error))}"


def confirm_isolate(name: str) -> str:
    return (f"🌐 Отрезать <b>{escape(name)}</b> от сети?\n\nНа связи останется только агент DeepSec. "
            "Вернуть сеть можно будет с кодом подтверждения 🔑.")


def confirm_terminate() -> str:
    return ("📵 Завершить <b>все</b> сеансы аккаунта, кроме сторожа и доверенных ⭐?\n\n"
            "На компьютерах (и на телефоне, если он не доверенный) придётся войти заново.")


def code_prompt(action: str, error: str = "") -> str:
    text = (f"🔑 Чтобы {CODE_LABELS.get(action, 'продолжить')}, отправьте 6-значный код "
            "из приложения-аутентификатора.")
    return f"{text}\n\n⛔ {escape(error)}" if error else text


HELP = """❓ <b>Как это работает</b>

На Windows работает агент: Windows сообщает ему о каждом чтении сессии Telegram (<code>tdata</code>). \
Чужой процесс он сразу завершает и запрещает ему сеть, а сюда приходит тревога.

Сервер с этим ботом держит <b>сторожа</b> — отдельный сеанс вашего аккаунта. При краже он сам завершает \
все сеансы, кроме доверенных ⭐, даже если вы офлайн, и на сутки включает <b>блокаду</b> новых входов.

🔑 — действия, которые ослабляют защиту. Для них нужен код из приложения-аутентификатора: \
если украдут ваш Telegram, вор не сможет выключить защиту.

Если компьютер долго не на связи — тоже придёт уведомление."""
