"""Состояние, переживающее перезапуск, журнал инцидентов и очередь неотправленных сообщений."""
from __future__ import annotations

import json
import logging
import os
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from .incidents import Incident

log = logging.getLogger(__name__)

T = TypeVar("T", bound="PersistentState")


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, path)


@dataclass
class PersistentState:
    path: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls: type[T], path: Path) -> T:
        try:
            data = json.loads(path.read_text("utf-8"))
        except FileNotFoundError:
            data = {}
        except (OSError, ValueError):
            log.exception("%s повреждён — начинаю с настроек по умолчанию", path.name)
            data = {}
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__ and k != "path"}
        return cls(**known, path=path)

    def save(self) -> None:
        if self.path is None:
            return
        data = asdict(self)
        data.pop("path")
        _write_json(self.path, data)


@dataclass
class AgentState(PersistentState):
    armed: bool = True
    isolated: bool = False
    blocked: dict[str, str] = field(default_factory=dict)  # имя правила брандмауэра -> путь exe
    trusted_hashes: dict[str, str] = field(default_factory=dict)  # sha256 -> путь exe (для показа)


class Journal:
    def __init__(self, path: Path | None, size: int = 300):
        self._path = path
        self._items: deque[Incident] = deque(maxlen=size)
        if path is not None and path.is_file():
            # Подхватываем хвост журнала, чтобы кнопки под старыми уведомлениями работали после перезапуска.
            with path.open(encoding="utf-8") as f:
                for line in deque(f, maxlen=size):
                    try:
                        self._items.append(Incident.from_json(json.loads(line)))
                    except (ValueError, KeyError, TypeError):
                        continue

    def add(self, incident: Incident) -> None:
        self._items.append(incident)
        if self._path is None:
            return
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(incident.to_json(), ensure_ascii=False) + "\n")
        except OSError:
            log.exception("Не удалось записать инцидент в журнал")

    def get(self, incident_id: str) -> Incident | None:
        return next((i for i in reversed(self._items) if i.id == incident_id), None)

    def last(self, n: int) -> list[Incident]:
        return list(self._items)[-n:]


class Outbox:
    """Сообщения для сервера, которые ещё не подтверждены. Хранятся на диске: тревога о краже дойдёт
    до сервера, даже если сети не было, а ПК успели перезагрузить."""

    def __init__(self, path: Path | None, limit: int = 200):
        self._path = path
        self._limit = limit
        self._items: list[dict] = []
        if path is not None and path.is_file():
            try:
                self._items = list(json.loads(path.read_text("utf-8")))[-limit:]
            except (OSError, ValueError):
                log.exception("outbox.json повреждён — очищаю")

    def add(self, key: str, message: dict) -> None:
        self._items.append({"key": key, "message": message})
        del self._items[:-self._limit]
        self._save()

    def ack(self, key: str) -> None:
        before = len(self._items)
        self._items = [i for i in self._items if i["key"] != key]
        if len(self._items) != before:
            self._save()

    def items(self) -> list[tuple[str, dict]]:
        return [(i["key"], i["message"]) for i in self._items]

    def _save(self) -> None:
        if self._path is not None:
            _write_json(self._path, self._items)
