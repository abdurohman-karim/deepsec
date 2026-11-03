"""python -m deepsec.server        — бот + сторож + приём агентов (запускает systemd)
python -m deepsec.server login  — вход сторожа в аккаунт (номер, код, облачный пароль)"""
from __future__ import annotations

import asyncio
import logging
import ssl
import sys
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand
from aiohttp import web

from .config import ServerConfig
from .core import Server
from .guard import GuardError, SessionGuard, interactive_login, make_client
from .handlers import build_router
from .texts import set_timezone
from .ui import TelegramNotifier

log = logging.getLogger("deepsec.server")


async def serve(cfg: ServerConfig) -> None:
    set_timezone(cfg.timezone)
    bot = Bot(cfg.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    notifier = TelegramNotifier(bot, cfg.owner_id)
    server = Server(cfg, notifier)

    dp = Dispatcher(server=server)
    dp.include_router(build_router(cfg.owner_id))

    tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    tls.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    runner = web.AppRunner(server.hub.app())
    await runner.setup()
    try:
        await web.TCPSite(runner, cfg.listen_host, cfg.listen_port, ssl_context=tls).start()
        log.info("Жду агентов на %s:%s", cfg.listen_host, cfg.listen_port)
    except OSError as e:
        # Бот и сторож нужны и без агентов — не падаем, а сообщаем владельцу.
        log.error("Не удалось открыть порт %s для агентов: %s", cfg.listen_port, e)
        notifier.send(f"⚠️ Не могу открыть порт {cfg.listen_port} для агентов ({e.strerror}). Бот и сторож "
                      "работают, но компьютеры не подключатся. Поменяйте LISTEN_PORT в .env на сервере и "
                      "выполните <code>systemctl restart deepsec-bot</code>.")

    tasks = [notifier.run(), server.watch_agents(), dp.start_polling(bot, handle_signals=False)]
    if cfg.api_id:
        guard = SessionGuard(make_client(Path(cfg.data_dir) / "guard", cfg.api_id, cfg.api_hash),
                             server.on_new_login)
        tasks.append(server.run_guard(guard))
    try:
        await bot.set_my_commands([BotCommand(command="menu", description="Меню")])
        await asyncio.gather(*tasks)
    finally:
        await runner.cleanup()
        await bot.session.close()


def login(cfg: ServerConfig) -> int:
    if not cfg.api_id:
        print("В .env нет TG_API_ID / TG_API_HASH — получите их на https://my.telegram.org → API development tools.")
        return 1
    print("Вход сторожа: номер телефона, код, затем, если включён, облачный пароль.")
    try:
        name = asyncio.run(interactive_login(Path(cfg.data_dir) / "guard", cfg.api_id, cfg.api_hash))
    except GuardError as e:
        print(f"⛔ {e}")
        return 1
    except KeyboardInterrupt:
        return 1
    print(f"✅ Сторож вошёл в аккаунт {name}. В списке устройств он называется «DeepSec Guard» — не завершайте его.")
    print("⚠️  Telegram разрешает завершать другие сеансы только сеансу старше 24 часов.")
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = ServerConfig.load()
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    if sys.argv[1:] == ["login"]:
        logging.getLogger("telethon").setLevel(logging.WARNING)  # без служебных строк при вводе кода
        return login(cfg)
    asyncio.run(serve(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
