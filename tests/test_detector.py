from __future__ import annotations

import asyncio

from conftest import DATA_DIR, DECOY, TDATA, event_xml

from deepsec.detector import FILE_SYSTEM_GUID, Detector
from deepsec.incidents import Kind, Severity
from deepsec.winevent import parse_event_xml

SELF_PID = 0x500
TELEGRAM = r"C:\Users\me\AppData\Roaming\Telegram Desktop\Telegram.exe"
STEALER = r"C:\Users\me\Downloads\crack.exe"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def trusted_only_telegram(path: str) -> bool:
    return path == TELEGRAM


def make(cfg, clock=None) -> Detector:
    return Detector(cfg, trusted_only_telegram, SELF_PID, clock or FakeClock())


def read(path: str, process: str, pid: str = "0x1a2c"):
    return parse_event_xml(event_xml(
        4663, ObjectName=path, ProcessName=process, ProcessId=pid,
        SubjectUserName="me", SubjectDomainName="PC", AccessMask="0x1",
    ))


def process(detector: Detector, ev):
    return asyncio.run(detector.process(ev))


def test_stealer_reading_key_datas_is_critical(cfg):
    inc = process(make(cfg), read(TDATA + r"\key_datas", STEALER))
    assert inc.kind is Kind.TDATA_ACCESS
    assert inc.severity is Severity.CRITICAL
    assert inc.pid == 0x1A2C
    assert inc.process_path == STEALER
    assert inc.respond


def test_path_matching_is_case_insensitive(cfg):
    inc = process(make(cfg), read(TDATA.upper() + r"\D877F783D5D3EF8C\maps", STEALER))
    assert inc is not None and inc.kind is Kind.TDATA_ACCESS


def test_trusted_telegram_is_ignored(cfg):
    assert process(make(cfg), read(TDATA + r"\key_datas", TELEGRAM)) is None


def test_similar_prefix_is_not_tdata(cfg):
    assert process(make(cfg), read(TDATA + r"_backup\key_datas", STEALER)) is None


def test_decoy_read_is_critical(cfg):
    inc = process(make(cfg), read(DECOY + r"\key_datas", STEALER))
    assert inc.kind is Kind.DECOY_ACCESS and inc.respond


def test_smb_read_by_system_has_no_process(cfg):
    inc = process(make(cfg), read(TDATA + r"\key_datas", "", pid="0x4"))
    assert inc.pid == 4 and inc.process_path is None
    assert "SMB" in inc.title


def test_selftest_canary_read_by_agent(cfg):
    clock = FakeClock()
    detector = make(cfg, clock)
    canary = DATA_DIR + r"\canary\selftest.bin"
    assert process(detector, read(canary, r"C:\Python\python.exe", pid=hex(SELF_PID))) is None
    assert detector.selftest_seen == clock.now


def test_canary_read_by_someone_else_does_not_count(cfg):
    detector = make(cfg)
    process(detector, read(DATA_DIR + r"\canary\selftest.bin", STEALER))
    assert detector.selftest_seen == float("-inf")


def logon(logon_type: str, user: str = "me", domain: str = "PC", ip: str = "-"):
    return parse_event_xml(event_xml(
        4624, LogonType=logon_type, TargetUserName=user, TargetDomainName=domain, IpAddress=ip,
        WorkstationName="ATTACKER",
    ))


def test_rdp_logon_is_critical(cfg):
    inc = process(make(cfg), logon("10", ip="203.0.113.5"))
    assert inc.kind is Kind.REMOTE_LOGON and inc.severity is Severity.CRITICAL
    assert inc.details["IP"] == "203.0.113.5"


def test_service_logons_are_ignored(cfg):
    detector = make(cfg)
    assert process(detector, logon("2", user="DWM-1", domain="Window Manager")) is None
    assert process(detector, logon("5", user="SYSTEM", domain="NT AUTHORITY")) is None
    assert process(detector, logon("2", user="PC$")) is None


def test_double_logon_event_is_merged(cfg):
    clock = FakeClock()
    detector = make(cfg, clock)
    assert process(detector, logon("2")) is not None
    assert process(detector, logon("2")) is None  # повышенный токен того же входа
    clock.now += 60
    assert process(detector, logon("2")) is not None


def test_network_logons_off_by_default(cfg):
    assert process(make(cfg), logon("3", ip="192.168.1.20")) is None


def failed(ip: str = "-"):
    return parse_event_xml(event_xml(4625, LogonType="2", TargetUserName="me", TargetDomainName="PC", IpAddress=ip))


def test_failed_logons_threshold(cfg):
    clock = FakeClock()
    detector = make(cfg, clock)
    assert process(detector, failed()) is None
    assert process(detector, failed()) is None
    inc = process(detector, failed())
    assert inc.kind is Kind.FAILED_LOGONS and inc.severity is Severity.WARNING
    assert process(detector, failed()) is None  # счётчик сброшен


def test_failed_logons_outside_window_do_not_add_up(cfg):
    clock = FakeClock()
    detector = make(cfg, clock)
    process(detector, failed())
    process(detector, failed())
    clock.now += cfg.failed_logon_window + 1
    assert process(detector, failed()) is None


def test_remote_failed_logons_are_critical(cfg):
    detector = make(cfg)
    for _ in range(cfg.failed_logon_threshold - 1):
        process(detector, failed("203.0.113.5"))
    inc = process(detector, failed("203.0.113.5"))
    assert inc.severity is Severity.CRITICAL and inc.details["IP"] == "203.0.113.5"


def test_audit_disabled(cfg):
    ev = parse_event_xml(event_xml(
        4719, SubcategoryGuid=FILE_SYSTEM_GUID.lower(), AuditPolicyChanges="%%8448, %%8450",
        SubjectUserName="evil", SubjectDomainName="PC",
    ))
    inc = process(make(cfg), ev)
    assert inc.kind is Kind.AUDIT_DISABLED and inc.details["кто"] == "PC\\evil"


def test_audit_enabled_is_not_alert(cfg):
    ev = parse_event_xml(event_xml(4719, SubcategoryGuid=FILE_SYSTEM_GUID, AuditPolicyChanges="%%8449, %%8451"))
    assert process(make(cfg), ev) is None


def test_log_cleared_from_user_data(cfg):
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        "<EventID>1102</EventID><EventRecordID>7</EventRecordID>"
        '<TimeCreated SystemTime="2026-11-03T10:15:30Z"/></System>'
        '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
        "<SubjectUserName>evil</SubjectUserName><SubjectDomainName>PC</SubjectDomainName>"
        "</LogFileCleared></UserData></Event>"
    )
    inc = process(make(cfg), parse_event_xml(xml))
    assert inc.kind is Kind.LOG_CLEARED and inc.details["кто"] == "PC\\evil"
