from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import Config

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
    sub.add_parser("setup", help="установка: аудит, ловушки, бот, автозапуск (от администратора)")
    sub.add_parser("check", help="диагностика: где tdata, кем подписан Telegram.exe")
    args = parser.parse_args(argv)

    if args.command == "run":
        return run()
    from .setup_win import check, setup
    return setup() if args.command == "setup" else check()


if __name__ == "__main__":
    sys.exit(main())
