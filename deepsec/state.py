"""Состояние агента, переживающее перезапуск, и журнал инцидентов."""
from __future__ import annotations

import json
import logging
import os
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .incidents import Incident

log = logging.getLogger(__name__)


@dataclass
class State:
    armed: bool = True
    isolated: bool = False
    blocked: dict[str, str] = field(default_factory=dict)  # имя правила брандмауэра -> путь exe
    trusted_hashes: dict[str, str] = field(default_factory=dict)  # sha256 -> путь exe (для показа)
    path: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path) -> State:
        try:
            data = json.loads(path.read_text("utf-8"))
        except FileNotFoundError:
            data = {}
        except (OSError, ValueError):
            log.exception("state.json повреждён — начинаю с настроек по умолчанию")
            data = {}
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__ and k != "path"}
        return cls(**known, path=path)

    def save(self) -> None:
        if self.path is None:
            return
        data = asdict(self)
        data.pop("path")
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        os.replace(tmp, self.path)


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
