"""Ядро сервера: инциденты от агентов, автозавершение украденных сеансов, блокада входов, действия из меню."""
from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections.abc import Awaitable
from dataclasses import dataclass, field
from pathlib import Path

from ..incidents import Incident, Kind, Severity
from ..state import Journal, PersistentState
from ..totp import TotpGuard, TotpResult
from .config import ServerConfig
from .guard import GuardError, GuardRevoked, GuardTooFresh, SessionGuard, SessionInfo
from .hub import OLD_AGENT, UNKNOWN_COMMAND, AgentLink, CommandResult, Hub

log = logging.getLogger(__name__)

SESSIONS_ACTION = "📵 Сеансы"
# После этих инцидентов считаем сессию украденной и завершаем сеансы аккаунта.
SESSION_THEFT = (Kind.TDATA_ACCESS, Kind.TOTP_BRUTEFORCE)
GUARD_HEALTH_INTERVAL = 300
GUARD_RECONNECT_DELAY = 30
OFFLINE_CHECK_INTERVAL = 15
BAD_AUTH_ALERT_INTERVAL = 3600


@dataclass
class ServerState(PersistentState):
    trusted_sessions: dict[str, str] = field(default_factory=dict)  # hash сеанса Telegram -> описание
    pending_terminate: str = ""  # непусто — сеансы ещё не удалось завершить, повторяем
    lockdown_until: float = 0.0  # unix-время: до него любой новый вход в аккаунт завершается
    menu_msg_id: int = 0  # «живое» сообщение меню у владельца
    agents: dict[str, float] = field(default_factory=dict)  # компьютер -> когда был на связи


class Notifier:
    """Интерфейс отправки уведомлений владельцу (реализация — в ui.py)."""

    def send(self, text: str, markup=None, silent: bool = False) -> None: ...

    def incident(self, inc: Incident) -> None: ...


class Server:
    def __init__(self, cfg: ServerConfig, notifier: Notifier | None = None):
        self.cfg = cfg
        data_dir = Path(cfg.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        self.state = ServerState.load(data_dir / "state.json")
        self.journal = Journal(data_dir / "incidents.jsonl")
        self.totp = TotpGuard(cfg.totp_secret)
        self.hub = Hub(cfg.agent_token, self, known=self.state.agents)
        self.notifier = notifier or Notifier()
        self.guard: SessionGuard | None = None
        self.guard_problem = "подключается…" if cfg.api_id else "не настроен (нет TG_API_ID / TG_API_HASH)"
        self.listed_sessions: list[SessionInfo] = []
        self._terminating = False
        self._last_bad_auth_alert = 0.0
        self._tasks: set[asyncio.Task] = set()

    def publish(self, inc: Incident) -> None:
        self.journal.add(inc)
        self.notifier.incident(inc)

    def _spawn(self, coro: Awaitable) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ---------- события агентов ----------

    async def on_incident(self, agent: AgentLink, inc: Incident, armed: bool) -> None:
        if self.journal.get(inc.id):
            return  # агент переотправил после обрыва связи — уже обработано
        inc.host = agent.name
        if armed and inc.respond and inc.kind in SESSION_THEFT and self.cfg.auto_terminate:
            inc.actions.append(self.terminate_sessions())
        self.publish(inc)

    async def on_online(self, agent: AgentLink, first_time: bool) -> None:
        self._remember(agent)
        if first_time:
            self.notifier.send(f"🖥 Новый компьютер подключён: <b>{agent.name}</b>")
        elif agent.offline_alerted:
            self.notifier.send(f"🟢 <b>{agent.name}</b> снова на связи", silent=True)
        agent.offline_alerted = False

    async def on_offline(self, agent: AgentLink) -> None:
        self._remember(agent)

    async def on_bad_auth(self, remote: str) -> None:
        if time.time() - self._last_bad_auth_alert > BAD_AUTH_ALERT_INTERVAL:
            self._last_bad_auth_alert = time.time()
            self.notifier.send(f"⚠️ Кто-то пытается подключиться к серверу как агент с неверным токеном: {remote}")

    def _remember(self, agent: AgentLink) -> None:
        self.state.agents[agent.name] = agent.last_seen
        self.state.save()

    async def watch_agents(self) -> None:
        while True:
            await asyncio.sleep(OFFLINE_CHECK_INTERVAL)
            for agent in self.hub.agents.values():
                silent_for = time.time() - agent.last_seen
                if not agent.online and not agent.offline_alerted and silent_for > self.cfg.offline_alert_seconds:
                    agent.offline_alerted = True
                    self.publish(Incident(
                        Kind.AGENT_OFFLINE, Severity.WARNING, f"{agent.name} не на связи",
                        details={"что это значит": "ПК выключен, без интернета — или агент кто-то остановил"},
                        host=agent.name,
                    ))

    # ---------- сторож аккаунта ----------

    @property
    def lockdown_active(self) -> bool:
        return time.time() < self.state.lockdown_until

    async def run_guard(self, guard: SessionGuard) -> None:
        while True:
            try:
                await guard.start()
                self.guard, self.guard_problem = guard, ""
                if self.state.pending_terminate:
                    self._spawn(self._terminate_loop())  # тревога случилась, пока не было связи
                tasks = {asyncio.ensure_future(guard.run()), asyncio.ensure_future(self._guard_health_loop(guard))}
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    task.result()
            except GuardRevoked as e:
                await self._guard_lost(e)
                return
            except Exception as e:
                log.exception("Сторож потерял связь с Telegram")
                self.guard, self.guard_problem = None, f"нет связи: {e}"
            try:
                await guard.close()
            except Exception:
                pass
            await asyncio.sleep(GUARD_RECONNECT_DELAY)

    async def _guard_health_loop(self, guard: SessionGuard) -> None:
        while True:
            await asyncio.sleep(GUARD_HEALTH_INTERVAL)
            try:
                await guard.sessions()
            except GuardRevoked:
                raise
            except Exception:
                log.warning("Сторож: проверка связи не удалась", exc_info=True)

    async def _guard_lost(self, error: Exception) -> None:
        if self.guard is None and self.guard_problem == str(error):
            return  # уже сообщили
        self.guard, self.guard_problem = None, str(error)
        self.publish(Incident(
            Kind.GUARD, Severity.CRITICAL,
            "Сторож аккаунта отключён — украденные сеансы НЕ будут завершаться автоматически",
            details={"причина": str(error), "исправить": "./deploy.sh root@СЕРВЕР login"},
        ))

    def terminate_sessions(self) -> str:
        """Запускает завершение всех сеансов, кроме сторожа и доверенных. Флаг в state переживает перезапуск,
        поэтому без связи с Telegram сервер доведёт дело до конца, как только она появится."""
        if not self.cfg.api_id:
            return f"{SESSIONS_ACTION}: ⚠️ сторож не настроен — завершите сеансы с телефона вручную!"
        self.state.pending_terminate = "1"
        self.state.save()
        if self.guard is None:
            return f"{SESSIONS_ACTION}: ⚠️ сторож не работает ({self.guard_problem}) — завершите сеансы с телефона вручную!"
        self._spawn(self._terminate_loop())
        return f"{SESSIONS_ACTION}: завершаю все сеансы аккаунта, кроме доверенных…"

    async def _terminate_loop(self) -> None:
        from .texts import terminated

        if self._terminating:
            return
        self._terminating = True
        delay, warned_fresh = 5, False
        try:
            while self.guard is not None and self.state.pending_terminate:
                try:
                    victims = await self.guard.terminate_except({int(h) for h in self.state.trusted_sessions})
                except GuardTooFresh as e:
                    if not warned_fresh:
                        warned_fresh = True
                        self.publish(Incident(
                            Kind.GUARD, Severity.CRITICAL, "Не могу завершить сеансы автоматически",
                            details={"причина": str(e),
                                     "что сделать": "СРОЧНО с телефона: Настройки → Устройства → завершить все другие сеансы"},
                        ))
                    delay = 600
                except GuardRevoked as e:
                    await self._guard_lost(e)
                    return
                except Exception:
                    log.exception("Не удалось завершить сеансы — повторю")
                    delay = min(delay * 2, 60)
                else:
                    self.state.pending_terminate = ""
                    self.state.lockdown_until = time.time() + self.cfg.lockdown_hours * 3600
                    self.state.save()
                    self.notifier.send(terminated(victims, self.cfg.lockdown_hours))
                    return
                await asyncio.sleep(delay)
        finally:
            self._terminating = False

    async def on_new_login(self, session_hash: int, description: str) -> None:
        if str(session_hash) in self.state.trusted_sessions:
            return
        inc = Incident(Kind.NEW_LOGIN, Severity.WARNING, "Новый вход в ваш аккаунт Telegram",
                       details={"устройство": description}, session=session_hash)
        if self.lockdown_active and self.guard is not None:
            inc.severity, inc.title = Severity.CRITICAL, "Новый вход в аккаунт во время блокады"
            inc.actions.append(await self.terminate_session(session_hash))
        self.publish(inc)

    async def terminate_session(self, session_hash: int) -> str:
        try:
            if self.guard is None:
                raise GuardError(f"сторож не работает ({self.guard_problem})")
            await self.guard.terminate(session_hash)
            return f"{SESSIONS_ACTION}: сеанс завершён"
        except Exception as e:
            log.exception("Не удалось завершить сеанс")
            return f"{SESSIONS_ACTION}: ошибка — {e}"

    async def list_sessions(self) -> list[SessionInfo]:
        if self.guard is None:
            raise GuardError(f"сторож не работает ({self.guard_problem})")
        self.listed_sessions = await self.guard.sessions()
        return self.listed_sessions

    def session_by_index(self, index: int) -> SessionInfo | None:
        return self.listed_sessions[index] if 0 <= index < len(self.listed_sessions) else None

    def check_totp(self, code: str) -> TotpResult:
        result = self.totp.check(code)
        if result.locked_now:
            inc = Incident(
                Kind.TOTP_BRUTEFORCE, Severity.CRITICAL,
                "Кто-то подбирает код подтверждения в боте — возможно, ваш аккаунт Telegram у злоумышленника",
                respond=True,
            )
            if self.cfg.auto_terminate:
                inc.actions.append(self.terminate_sessions())
            self.publish(inc)
        return result

    # ---------- экран и программы компьютера ----------

    async def screenshot(self, name: str) -> tuple[bytes | None, CommandResult]:
        """JPEG экрана (None — не получилось) и ответ агента: в нём пользователь, активное окно или ошибка."""
        result = await self.hub.command(name, "screenshot")
        jpeg = (result.data or {}).get("jpeg") if result.ok else None
        return (base64.b64decode(jpeg) if jpeg else None), result

    async def apps(self, name: str) -> CommandResult:
        return await self.hub.command(name, "apps")

    # ---------- действия из меню и кнопок ----------

    async def perform(self, action: str, target: str = "", extra: str = "") -> str:
        """Выполняет действие и возвращает текст для владельца. Код TOTP к этому моменту уже проверен."""
        if action in AGENT_ACTIONS:
            return _fmt(await self.hub.command(target, AGENT_ACTIONS[action], **_agent_args(action, extra)))
        if action in INCIDENT_ACTIONS:
            inc = self.journal.get(target)
            if inc is None or not inc.host:
                return "⚠️ Инцидент не найден"
            if action == "kill" and not inc.pid:
                return "⚠️ В инциденте нет процесса"
            if action != "kill" and not inc.process_path:
                return "⚠️ В инциденте нет пути к программе"
            result = await self.hub.command(inc.host, action, pid=inc.pid, path=inc.process_path)
            inc.actions.append(result.text)
            return _fmt(result)
        if action == "terminate":
            return self.terminate_sessions()
        if action == "lockdown_off":
            self.state.lockdown_until = 0.0
            self.state.save()
            return "🔓 Блокада снята — можно входить в Telegram Desktop заново"
        if action in ("sess_kill", "sess_trust", "sess_untrust"):
            session = self.session_by_index(int(target or -1))
            if session is None:
                return "⚠️ Список сеансов устарел — откройте его заново"
            if action == "sess_kill":
                return await self.terminate_session(session.hash)
            if action == "sess_trust":
                self.state.trusted_sessions[str(session.hash)] = session.describe()
            else:
                self.state.trusted_sessions.pop(str(session.hash), None)
            self.state.save()
            return "⭐ Доверенный — не будет завершаться автоматически" if action == "sess_trust" else "Доверие снято"
        if action == "login_kill":
            inc = self.journal.get(target)
            if inc is None or inc.session is None:
                return "⚠️ Инцидент не найден"
            result = await self.terminate_session(inc.session)
            inc.actions.append(result)
            return result
        return f"⚠️ Неизвестное действие {action}"


# Действия меню компьютера -> команда агенту.
AGENT_ACTIONS = {
    "lock": "lock", "isolate": "isolate", "unisolate": "unisolate", "arm": "arm", "disarm": "disarm",
    "selftest": "selftest", "unblock": "unblock", "unblock_all": "unblock",
    "pet_on": "pet", "pet_say": "pet", "pet_off": "pet_off",
}
INCIDENT_ACTIONS = ("kill", "block", "quarantine", "trust")


def _agent_args(action: str, extra: str) -> dict:
    if action == "unblock":
        return {"rule": extra}
    if action == "unblock_all":
        return {"rule": "*"}
    if action == "pet_on":
        return {"mood": extra}
    if action == "pet_say":  # свой текст — со следящим питомцем
        return {"mood": "watch", "text": extra}
    return {}


def _fmt(result: CommandResult) -> str:
    if result.text.startswith(UNKNOWN_COMMAND):
        return f"⚠️ {OLD_AGENT}"
    return f"{'✅' if result.ok else '⚠️'} {result.text}"
