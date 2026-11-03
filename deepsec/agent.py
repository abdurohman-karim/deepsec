"""Агент: связывает журнал событий, детектор, реакцию и бота в одном asyncio-процессе."""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import time
from collections.abc import Awaitable
from datetime import datetime, timezone
from pathlib import Path

import psutil

from . import response, winacl
from .bot import Notifier, build_dispatcher, create_bot, set_commands
from .config import Config
from .detector import Detector, norm_path
from .incidents import Incident, Kind, Severity
from .monitors.eventlog import SecurityLogSubscription
from .monitors.processes import RemoteToolWatcher
from .state import Journal, State
from .totp import TotpGuard, TotpResult
from .trust import TrustChecker, sha256_file
from .winevent import parse_event_xml

log = logging.getLogger(__name__)

FILE_INCIDENTS = (Kind.TDATA_ACCESS, Kind.DECOY_ACCESS)
MERGE_WINDOW = 60  # сек: повторные чтения тем же процессом дописываются в первый инцидент
NOTIFY_DELAY = 1.5  # сек: даём стилеру «дочитать», чтобы в уведомлении был полный список файлов
SELFTEST_TIMEOUT = 15


class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        data_dir = Path(cfg.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        self.state = State.load(data_dir / "state.json")
        self.journal = Journal(data_dir / "incidents.jsonl")
        self.trust = TrustChecker(cfg.trusted, lambda: self.state.trusted_hashes.keys())
        self.detector = Detector(cfg, self.trust, os.getpid())
        self.totp = TotpGuard(cfg.totp_secret)
        self.notifier: Notifier | None = None
        self.audit_ok: bool | None = None
        self.started = datetime.now(timezone.utc)
        self.own_exe = psutil.Process().exe()
        self._events: asyncio.Queue[str] = asyncio.Queue(maxsize=10_000)
        self._recent: dict[tuple, tuple[Incident, float]] = {}
        self._tasks: set[asyncio.Task] = set()

    # ---------- запуск ----------

    async def run(self) -> None:
        bot = create_bot(self.cfg.bot_token)
        dp = build_dispatcher(self)
        self.notifier = Notifier(bot, self.cfg.owner_id)

        # Мониторинг включаем первым делом — сеть при загрузке Windows может появиться не сразу.
        subscription = SecurityLogSubscription(asyncio.get_running_loop(), self._events)
        subscription.start()
        mode = "🟢 авто-реакция" if self.state.armed else "🟡 только уведомления"
        self.notifier.send(f"🛡 DeepSec запущен на <b>{platform.node()}</b>. Режим: {mode}. Проверяю аудит…")
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(asyncio.to_thread(self._reapply_audit))
                tg.create_task(set_commands(bot))
                tg.create_task(self.notifier.run())
                tg.create_task(self._consume_events())
                tg.create_task(self._selftest_loop())
                tg.create_task(self._watch_remote_tools())
                tg.create_task(dp.start_polling(bot, handle_signals=False))
        finally:
            subscription.close()
            await bot.session.close()

    def _reapply_audit(self) -> None:
        # Если вы перелогинились в Telegram, папка аккаунта в tdata новая и без аудита — повесим заново.
        for tdata in self.cfg.tdata_dirs:
            try:
                if Path(tdata).is_dir():
                    winacl.protect_tdata(Path(tdata))
            except Exception:
                log.exception("Не удалось включить аудит на %s", tdata)

    # ---------- обработка событий ----------

    async def _consume_events(self) -> None:
        while True:
            xml = await self._events.get()
            try:
                incident = await self.detector.process(parse_event_xml(xml))
                if incident:
                    await self.handle(incident)
            except Exception:
                log.exception("Ошибка при обработке события")

    async def handle(self, inc: Incident) -> None:
        if inc.kind in FILE_INCIDENTS:
            key = (inc.kind, inc.pid, inc.process_path)
            now = time.monotonic()
            self._recent = {k: v for k, v in self._recent.items() if now - v[1] < MERGE_WINDOW}
            if key in self._recent:
                prev = self._recent[key][0]
                prev.files.extend(f for f in inc.files if f not in prev.files)
                return
            self._recent[key] = (inc, now)

        # Сначала реагируем (каждая миллисекунда на счету), потом уведомляем.
        if inc.respond and self.state.armed:
            await self._auto_respond(inc)
        delay = NOTIFY_DELAY if inc.kind in FILE_INCIDENTS else 0
        self._spawn(self._publish(inc, delay))

    async def _publish(self, inc: Incident, delay: float) -> None:
        if delay:
            await asyncio.sleep(delay)
        self.journal.add(inc)
        if self.notifier:
            self.notifier.incident(inc)

    async def _auto_respond(self, inc: Incident) -> None:
        if self.cfg.auto_kill and not response.is_protected(inc.pid, inc.process_path):
            inc.actions.append(await self.act_kill(inc.pid, inc.process_path))
        if self.cfg.auto_firewall and not response.is_protected_path(inc.process_path):
            inc.actions.append(await self.act_block(inc.process_path))
        if self.cfg.auto_lock:
            inc.actions.append(await self.act_lock())

    def _spawn(self, coro: Awaitable) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ---------- самопроверка и мониторы ----------

    async def run_selftest(self) -> bool:
        """Читаем свой canary-файл с SACL и ждём, что Windows пришлёт про это событие 4663."""
        started = time.monotonic()
        await asyncio.to_thread(_touch_canary, Path(self.cfg.canary_file))
        deadline = started + SELFTEST_TIMEOUT
        while time.monotonic() < deadline:
            if self.detector.selftest_seen >= started:
                return True
            await asyncio.sleep(0.5)
        return False

    async def _selftest_loop(self) -> None:
        await asyncio.sleep(3)
        while True:
            ok = await self.run_selftest()
            if ok != self.audit_ok:
                if ok:
                    self.notifier.send("✅ Самопроверка: аудит работает, чтение tdata отслеживается", silent=True)
                else:
                    await self.handle(Incident(
                        Kind.SELFTEST, Severity.CRITICAL,
                        "Самопроверка провалена: Windows не сообщает о чтении файлов",
                        details={"проверьте": "запущен ли агент от SYSTEM и выполнен ли setup; не отключал ли кто-то аудит"},
                    ))
            self.audit_ok = ok
            await asyncio.sleep(self.cfg.selftest_interval)

    async def _watch_remote_tools(self) -> None:
        watcher = RemoteToolWatcher()
        while True:
            for found in await asyncio.to_thread(watcher.poll):
                await self.handle(Incident(
                    Kind.REMOTE_TOOL, Severity.WARNING, f"Запущена программа удалённого доступа: {found.tool}",
                    pid=found.pid, process_path=found.exe or None,
                ))
            await asyncio.sleep(self.cfg.process_poll_interval)

    # ---------- действия (вызываются авто-реакцией и кнопками бота) ----------

    def _refuse_own_exe(self, path: str) -> None:
        # Тот же python.exe, на котором работает агент: запрет сети отрезал бы самого агента от бота.
        if norm_path(path) == norm_path(self.own_exe):
            raise response.ResponseError("это интерпретатор самого агента — не блокирую, иначе бот потеряет связь")

    async def _safe(self, label: str, coro: Awaitable[str]) -> str:
        try:
            return f"{label}: {await coro}"
        except Exception as e:
            log.exception(label)
            return f"{label}: ошибка — {e}"

    async def act_kill(self, pid: int, path: str | None) -> str:
        return await self._safe("🔪 Процесс", asyncio.to_thread(response.kill_tree, pid, path))

    async def act_block(self, path: str) -> str:
        async def do() -> str:
            self._refuse_own_exe(path)
            name = await asyncio.to_thread(response.block_program, path)
            self.state.blocked[name] = path
            self.state.save()
            return f"сеть запрещена (правило {name})"
        return await self._safe("🧱 Брандмауэр", do())

    async def act_unblock(self, rule: str) -> str:
        async def do() -> str:
            await asyncio.to_thread(response.unblock, rule)
            self.state.blocked.pop(rule, None)
            self.state.save()
            return f"правило {rule} удалено"
        return await self._safe("🧱 Брандмауэр", do())

    async def act_quarantine(self, path: str) -> str:
        async def do() -> str:
            self._refuse_own_exe(path)
            target = await asyncio.to_thread(response.quarantine, path, self.cfg.data_dir)
            return f"файл перемещён в {target}"
        return await self._safe("📦 Карантин", do())

    async def act_lock(self) -> str:
        return await self._safe("🔒 Сеансы", asyncio.to_thread(response.lock_sessions))

    async def act_isolate(self) -> str:
        async def do() -> str:
            await asyncio.to_thread(response.isolate, psutil.Process().exe())
            self.state.isolated = True
            self.state.save()
            return "ПК отрезан от сети, на связи только агент. Вернуть: /unisolate КОД"
        return await self._safe("🌐 Изоляция", do())

    async def act_unisolate(self) -> str:
        async def do() -> str:
            await asyncio.to_thread(response.unisolate)
            self.state.isolated = False
            self.state.save()
            return "сеть восстановлена"
        return await self._safe("🌐 Изоляция", do())

    async def trust_process(self, path: str) -> str:
        async def do() -> str:
            digest = await asyncio.to_thread(sha256_file, path)
            self.state.trusted_hashes[digest] = path
            self.state.save()
            self.trust.invalidate()
            return f"{path} добавлен в доверенные (SHA-256 {digest[:16]}…). Если exe изменится — доверие пропадёт"
        return await self._safe("✅ Доверие", do())

    def set_armed(self, armed: bool) -> None:
        self.state.armed = armed
        self.state.save()

    def check_totp(self, code: str) -> TotpResult:
        result = self.totp.check(code)
        if result.locked_now:
            self._spawn(self.handle(Incident(
                Kind.TOTP_BRUTEFORCE, Severity.CRITICAL,
                "Кто-то подбирает TOTP-код в боте — возможно, ваш аккаунт Telegram у злоумышленника",
                details={"что сделать": "с телефона: Настройки → Устройства → завершить все другие сеансы"},
            )))
        return result

    def status_text(self) -> str:
        audit = {None: "⏳ проверяется", True: "✅ работает", False: "❌ НЕ работает"}[self.audit_ok]
        uptime = datetime.now(timezone.utc) - self.started
        lines = [
            f"🛡 <b>DeepSec</b> на {platform.node()}",
            f"Режим: {'🟢 авто-реакция' if self.state.armed else '🟡 только уведомления'}",
            f"Аудит чтения tdata: {audit}",
            f"Изоляция сети: {'🔴 включена' if self.state.isolated else 'выключена'}",
            f"Работает: {str(uptime).split('.')[0]}",
            f"Защищаемые tdata: {len(self.cfg.tdata_dirs)}, ловушки: {len(self.cfg.decoy_dirs)}",
            f"Блокировок в брандмауэре: {len(self.state.blocked)}, доверенных exe: {len(self.state.trusted_hashes)}",
        ]
        return "\n".join(lines)


def _touch_canary(path: Path) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(os.urandom(64))
    with path.open("rb") as f:
        f.read(1)
