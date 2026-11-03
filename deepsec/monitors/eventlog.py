"""Подписка в реальном времени на журнал Security через EvtSubscribe (нужны права администратора/SYSTEM)."""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)

# 4663 — доступ к объекту (наш SACL на tdata), 4624/4625 — входы, 4719 — изменена политика аудита,
# 1102 — журнал очищен.
QUERY = "*[System[(EventID=4663 or EventID=4624 or EventID=4625 or EventID=4719 or EventID=1102)]]"


class SecurityLogSubscription:
    def __init__(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue[str]):
        self._loop = loop
        self._queue = queue
        self._handle = None

    def start(self) -> None:
        import win32evtlog

        def on_event(action, _context, event):
            # Вызывается из потока Windows — в asyncio передаём только через call_soon_threadsafe.
            if action == win32evtlog.EvtSubscribeActionDeliver:
                try:
                    xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                except Exception:
                    log.exception("EvtRender не смог отрисовать событие")
                    return 0
                self._loop.call_soon_threadsafe(self._enqueue, xml)
            else:
                log.error("Ошибка подписки на журнал Security: %s", event)
            return 0

        self._handle = win32evtlog.EvtSubscribe(
            "Security",
            win32evtlog.EvtSubscribeToFutureEvents,
            Query=QUERY,
            Callback=on_event,
            Context=self,
        )

    def _enqueue(self, xml: str) -> None:
        try:
            self._queue.put_nowait(xml)
        except asyncio.QueueFull:
            log.warning("Очередь событий переполнена — событие пропущено")

    def close(self) -> None:
        self._handle = None
