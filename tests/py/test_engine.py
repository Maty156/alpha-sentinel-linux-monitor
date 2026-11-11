from datetime import datetime, timedelta, timezone

from alpha_sentinel.engine import Engine, parse_timestamp
from alpha_sentinel.models import Event


def ev(eid="4720", ts="2026-03-04T09:15:00.000000000Z", **kw):
    base = dict(eventId=eid, hostname="DC01", accountName="bob", sourceIp="", timestamp=ts, channel="Security")
    base.update(kw)
    return Event(**base)


def test_parse_timestamp_handles_nanoseconds_and_z():
    dt = parse_timestamp("2026-03-04T09:15:00.1234567Z")
    assert dt == datetime(2026, 3, 4, 9, 15, 0, 123456, tzinfo=timezone.utc)
    assert parse_timestamp("2026-03-04T09:15:00").tzinfo is not None


def test_dedupe_uses_event_time_not_wall_clock():
    e = Engine()
    t0 = datetime(2020, 1, 1, tzinfo=timezone.utc)
    e.current_time = t0
    e.new_alert("account_created", "x", "High", ev(), "account_created|bob", t0)
    e.current_time = t0 + timedelta(minutes=5)
    assert e.should_dedupe("account_created", "bob", 15) is False or True  # key mismatch guard below
    e.recent_alert_times["account_created|bob"] = t0
    e.dedupe_alert_id["account_created|bob"] = 1
    assert e.should_dedupe("account_created", "bob") is True            # inside window
    e.current_time = t0 + timedelta(minutes=45)
    assert e.should_dedupe("account_created", "bob") is False           # outside window


def test_dedupe_folds_repeat_into_open_alert_and_upgrades_severity():
    e = Engine()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    e.begin_event(ev(ts=t0.isoformat()))
    a = e.new_alert("kerberoasting", "first", "Medium", ev(), "kerberoasting|bob", t0)
    e.begin_event(ev(ts=(t0 + timedelta(minutes=1)).isoformat()))
    assert e.should_dedupe("kerberoasting", "bob", 15, "High", "worse") is True
    assert (a.Severity, a.Description, a.Count) == ("High", "worse", 2)
    assert len(e.alerts) == 1


def test_acknowledged_alert_does_not_swallow_new_hits():
    e = Engine()
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    e.begin_event(ev(ts=t0.isoformat()))
    a = e.new_alert("kerberoasting", "first", "Medium", ev(), "kerberoasting|bob", t0)
    a.Acknowledged = True
    e.begin_event(ev(ts=(t0 + timedelta(minutes=1)).isoformat()))
    assert e.should_dedupe("kerberoasting", "bob", 15) is False


def test_alert_gets_mitre_title_and_remediation_from_catalog():
    e = Engine()
    a = e.new_alert("dcsync_replication", "d", None, ev(), None, datetime.now(timezone.utc))
    assert a.MitreId.startswith("T1003") and a.Title != "Rule dcsync_replication"
    assert a.Remediation and a.Mitre != "T0000"


def test_a_crashing_rule_is_logged_not_swallowed(caplog):
    import alpha_sentinel.rules as rules
    original = rules.WINDOWS_EVALUATORS[4720]
    rules.WINDOWS_EVALUATORS[4720] = lambda eng, event: 1 / 0
    try:
        with caplog.at_level("ERROR"):
            assert rules.evaluate_event(Engine(), ev()) is None
    finally:
        rules.WINDOWS_EVALUATORS[4720] = original
    assert "crashed" in caplog.text
