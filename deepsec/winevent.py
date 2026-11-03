"""Разбор XML событий журнала Windows (то, что отдаёт EvtRender)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?")


@dataclass(frozen=True)
class WinEvent:
    event_id: int
    record_id: int
    time: datetime
    data: dict[str, str]

    def get(self, key: str) -> str:
        return self.data.get(key) or ""


def _parse_time(value: str | None) -> datetime:
    match = _TIME_RE.match(value or "")
    if not match:
        return datetime.now(timezone.utc)
    base, fraction = match.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    return datetime.fromisoformat(base).replace(microsecond=micro, tzinfo=timezone.utc)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_event_xml(xml: str) -> WinEvent:
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("в событии нет блока System")
    created = system.find("e:TimeCreated", NS)

    data: dict[str, str] = {}
    for item in root.iterfind("e:EventData/e:Data", NS):
        if name := item.get("Name"):
            data[name] = (item.text or "").strip()
    # Некоторые события (например, 1102 «журнал очищен») кладут поля в UserData.
    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        for elem in user_data.iter():
            if len(elem) == 0 and elem.text:
                data.setdefault(_local_name(elem.tag), elem.text.strip())

    return WinEvent(
        event_id=int(system.findtext("e:EventID", default="0", namespaces=NS)),
        record_id=int(system.findtext("e:EventRecordID", default="0", namespaces=NS)),
        time=_parse_time(created.get("SystemTime") if created is not None else None),
        data=data,
    )
