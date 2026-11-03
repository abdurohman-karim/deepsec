from __future__ import annotations

from deepsec.bot import Act, format_incident, incident_keyboard
from deepsec.incidents import Incident, Kind, Severity


def test_incident_message_is_escaped_and_has_hint():
    inc = Incident(
        Kind.TDATA_ACCESS, Severity.CRITICAL, "Чужой процесс <b>",
        pid=1234, process_path=r"C:\Users\me\x<y>.exe",
        files=[rf"C:\t\f{i}" for i in range(7)], actions=["🔪 Процесс: завершено процессов: 1"],
    )
    text = format_incident(inc)
    assert "&lt;b&gt;" in text and "x&lt;y&gt;.exe" in text
    assert "(+2)" in text
    assert "Завершить все другие сеансы" in text


def test_keyboard_buttons():
    inc = Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=1234, process_path=r"C:\x.exe")
    actions = [Act.unpack(b.callback_data).action for row in incident_keyboard(inc).inline_keyboard for b in row]
    assert actions == ["kill", "block", "quarantine", "lock", "isolate"]
    assert all(len(b.callback_data) <= 64 for row in incident_keyboard(inc).inline_keyboard for b in row)

    smb = Incident(Kind.TDATA_ACCESS, Severity.CRITICAL, "t", pid=4)
    actions = [Act.unpack(b.callback_data).action for row in incident_keyboard(smb).inline_keyboard for b in row]
    assert actions == ["lock", "isolate"]

    assert incident_keyboard(Incident(Kind.LOCAL_LOGON, Severity.INFO, "вход")) is None
