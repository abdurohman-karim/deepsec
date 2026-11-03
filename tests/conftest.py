from __future__ import annotations

import pytest

from deepsec.config import Config

TDATA = r"C:\Users\me\AppData\Roaming\Telegram Desktop\tdata"
DECOY = r"C:\Users\me\AppData\Roaming\AyuGram Desktop\tdata"
DATA_DIR = r"C:\ProgramData\DeepSec"

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event_xml(event_id: int, **data: str) -> str:
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="{EVENT_NS}"><System>'
        f"<EventID>{event_id}</EventID><EventRecordID>42</EventRecordID>"
        '<TimeCreated SystemTime="2026-11-03T10:15:30.1234567Z"/>'
        f"</System><EventData>{fields}</EventData></Event>"
    )


@pytest.fixture
def cfg() -> Config:
    return Config(
        bot_token="123:abc",
        owner_id=1,
        totp_secret="JBSWY3DPEHPK3PXP",
        tdata_dirs=(TDATA,),
        decoy_dirs=(DECOY,),
        data_dir=DATA_DIR,
    )
