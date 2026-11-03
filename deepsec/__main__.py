from __future__ import annotations

import argparse
import asyncio
import importlib
import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import Config
from .protocol import PET_MOODS

log = logging.getLogger("deepsec")


def setup_logging(data_dir: str) -> None:
    handlers: list[logging.Handler] = [
        RotatingFileHandler(Path(data_dir) / "agent.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8"),
    ]
    if sys.stderr is not None:  # у pythonw.exe консоли нет
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=handlers)


def run() -> int:
    from .agent import Agent

    cfg = Config.load()
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    setup_logging(cfg.data_dir)
    while True:
        try:
            asyncio.run(Agent(cfg).run())
        except KeyboardInterrupt:
            return 0
        except Exception:
            log.exception("Агент упал — перезапуск через 10 секунд")
        time.sleep(10)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="deepsec", description="Windows-агент DeepSec (бот — в deepsec.server)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="запустить агента (обычно это делает планировщик от SYSTEM)")
    setup_cmd = sub.add_parser("setup", help="установка: аудит, ловушки, подключение к серверу, автозапуск")
    setup_cmd.add_argument("--server", default="", help="IP или домен сервера")
    setup_cmd.add_argument("--port", default="", help="порт агентов (LISTEN_PORT на сервере)")
    setup_cmd.add_argument("--fingerprint", default="", help="SHA-256 отпечаток сертификата сервера")
    setup_cmd.add_argument("--token", default="", help="AGENT_TOKEN с сервера")
    setup_cmd.add_argument("--name", default="", help="имя компьютера в боте")
    setup_cmd.add_argument("--yes", action="store_true", help="не задавать вопросов (для установщика)")
    sub.add_parser("check", help="диагностика: где tdata, кем подписан Telegram.exe")
    sub.add_parser("uninstall", help="убрать задачу, правила брандмауэра, ловушки и настройки")
    sub.add_parser("version", help="версия; заодно проверяет, что сборка цела")
    desktop_cmd = sub.add_parser("desktop", help="служебная: агент запускает её в сеансе пользователя")
    desktop_cmd.add_argument("what", choices=("screenshot", "apps", "close"))
    desktop_cmd.add_argument("args", nargs="*", help="для close: PID и HWND окна")
    pet_cmd = sub.add_parser("pet", help="пиксельный питомец в углу экрана (агент запускает его по команде из бота)")
    pet_cmd.add_argument("mood", choices=PET_MOODS)
    pet_cmd.add_argument("--text", default="", help="своя надпись вместо стандартной")
    pet_cmd.add_argument("--minutes", type=float, default=120, help="через сколько минут исчезнуть")
    for cmd in sub.choices.values():
        cmd.add_argument("--pause", action="store_true", help="ждать Enter перед выходом (окно не закроется)")
    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        return 1
    except Exception as e:  # из установщика окно закроется — покажем причину по-человечески
        if not args.pause:
            raise
        print(f"\n⛔ Ошибка: {e}")
        return 1
    finally:
        if args.pause:
            input("\nНажмите Enter, чтобы закрыть окно…")


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "run":
        return run()
    if args.command == "desktop":
        from . import desktop

        return desktop.helper_main(args.what, args.args)
    if args.command == "pet":
        from . import pet

        return pet.main(args.mood, args.text, args.minutes)
    if args.command == "version":
        from . import __version__

        # Импорт проверяет, что в сборке PyInstaller есть всё нужное агенту (CI запускает это после сборки).
        windows_only = ("win32evtlog", "win32ts", "win32profile", "win32pipe", "win32file", "win32event",
                        "win32service", "win32gui", "win32process", "PIL.ImageGrab")
        for module in ("deepsec.agent", "deepsec.setup_win", "deepsec.pet",
                       *(windows_only if sys.platform == "win32" else ())):
            importlib.import_module(module)
        print(__version__)
        return 0
    from . import setup_win

    if args.command == "setup":
        opts = setup_win.SetupOptions(server=args.server, port=args.port, fingerprint=args.fingerprint,
                                      token=args.token, name=args.name, yes=args.yes)
        return setup_win.setup(opts)
    if args.command == "uninstall":
        return setup_win.uninstall()
    return setup_win.check()


if __name__ == "__main__":
    sys.exit(main())
