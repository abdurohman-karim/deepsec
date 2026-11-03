"""Настройки сервера (.env в /home/bots/deepsec)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import dotenv_values

from ..config import ConfigError, parse_flag


@dataclass(frozen=True)
class ServerConfig:
    bot_token: str
    owner_id: int
    totp_secret: str
    agent_token: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    tls_cert: str = "data/tls/cert.pem"
    tls_key: str = "data/tls/key.pem"
    data_dir: str = "data"
    # Сторож (Telethon): ключи с my.telegram.org. Без них автозавершение сеансов выключено.
    api_id: int | None = None
    api_hash: str = ""
    auto_terminate: bool = True
    lockdown_hours: float = 24
    offline_alert_seconds: int = 180
    timezone: str = "Asia/Tashkent"  # для времени в сообщениях

    @classmethod
    def load(cls, env_file: str = ".env") -> ServerConfig:
        env = {**{k: v for k, v in dotenv_values(env_file).items() if v}, **os.environ}
        return cls.from_mapping(env)

    @classmethod
    def from_mapping(cls, env: dict[str, str]) -> ServerConfig:
        missing = [k for k in ("BOT_TOKEN", "OWNER_ID", "TOTP_SECRET", "AGENT_TOKEN") if not env.get(k)]
        if missing:
            raise ConfigError(f"В .env не заданы: {', '.join(missing)} (см. .env.example)")
        return cls(
            bot_token=env["BOT_TOKEN"],
            owner_id=int(env["OWNER_ID"]),
            totp_secret=env["TOTP_SECRET"],
            agent_token=env["AGENT_TOKEN"],
            listen_host=env.get("LISTEN_HOST") or "0.0.0.0",
            listen_port=int(env.get("LISTEN_PORT") or 8443),
            tls_cert=env.get("TLS_CERT") or "data/tls/cert.pem",
            tls_key=env.get("TLS_KEY") or "data/tls/key.pem",
            data_dir=env.get("DATA_DIR") or "data",
            api_id=int(env["TG_API_ID"]) if env.get("TG_API_ID") else None,
            api_hash=env.get("TG_API_HASH") or "",
            auto_terminate=parse_flag(env.get("AUTO_TERMINATE"), True),
            lockdown_hours=float(env.get("LOCKDOWN_HOURS") or 24),
            offline_alert_seconds=int(env.get("OFFLINE_ALERT_SECONDS") or 180),
            timezone=env.get("TIMEZONE") or "Asia/Tashkent",
        )
