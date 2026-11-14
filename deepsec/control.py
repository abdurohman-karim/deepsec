"""Локальный канал агента для окна DeepSec: http://127.0.0.1:PORT — только с этого компьютера.

Окно работает от пользователя и без прав администратора, а обновляет агент (SYSTEM): окно просит его
проверить, скачать или установить обновление и показывает прогресс. Через канал можно только это —
и поставить только опубликованный релиз с совпавшим SHA-256, так что вреда от чужого запроса нет.
От веб-страниц канал закрыт: нужен свой заголовок, а запросы браузера с Origin отклоняются.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from typing import Any

from aiohttp import web

from .protocol import LOCAL_HEADER, LOCAL_PORT
from .update import UpdateError, Updater

log = logging.getLogger(__name__)


def build_app(updater: Updater) -> web.Application:
    @web.middleware
    async def only_window(request: web.Request, handler):
        if request.headers.get(LOCAL_HEADER) != "1" or request.headers.get("Origin"):
            return web.json_response({"error": "forbidden"}, status=403)
        return await handler(request)

    async def state(request: web.Request) -> web.Response:
        return web.json_response(updater.snapshot())

    async def check(request: web.Request) -> web.Response:
        await updater.check()
        return web.json_response(updater.snapshot())

    async def download(request: web.Request) -> web.Response:
        updater.start(install_after=False)
        return web.json_response(updater.snapshot())

    async def install(request: web.Request) -> web.Response:
        try:
            await updater.install(reopen_window=True)
        except UpdateError as e:
            return web.json_response({**updater.snapshot(), "error": str(e)}, status=409)
        return web.json_response(updater.snapshot())

    app = web.Application(middlewares=[only_window])
    app.router.add_get("/update", state)
    app.router.add_post("/update/check", check)
    app.router.add_post("/update/download", download)
    app.router.add_post("/update/install", install)
    return app


async def serve(updater: Updater, port: int = LOCAL_PORT) -> None:
    """Держит канал, пока работает агент. Порт занят — окно просто не сможет обновлять, защита работает."""
    runner = web.AppRunner(build_app(updater), access_log=None)
    await runner.setup()
    try:
        await web.TCPSite(runner, "127.0.0.1", port).start()
    except OSError as e:
        log.warning("Локальный канал для окна DeepSec не открыт (порт %s): %s", port, e)
        await runner.cleanup()
        return
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def call(path: str, method: str = "GET", port: int = LOCAL_PORT, timeout: float = 5) -> dict[str, Any]:
    """Запрос окна к агенту. OSError — агент не запущен или канал недоступен."""
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                     data=b"" if method == "POST" else None, headers={LOCAL_HEADER: "1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:  # 409 и т.п. — в теле тот же снимок состояния с ошибкой
        return json.load(e)
