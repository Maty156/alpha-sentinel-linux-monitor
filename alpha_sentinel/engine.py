"""Detection engine - evaluation, dedupe, and threshold windows."""

import re
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from alpha_sentinel.models import Alert, Event
from alpha_sentinel.rule_meta import WINDOWS_RULE_META
from alpha_sentinel.catalog import LINUX_RULE_META

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
MAX_ALERT_EVENTS = 50  # contributing events kept per alert
MAX_ALERTS = 10000  # in-memory cap; oldest alerts are dropped beyond this

_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_timestamp(ts: Optional[str]) -> datetime:
    """Parse an event timestamp into a timezone-aware UTC datetime.

    Handles the 7-9 digit fractional seconds Windows writes ("...00.0000000Z"),
    which Python < 3.11 cannot parse, and naive timestamps (assumed UTC).
    Falls back to "now" only when the value is missing or unparseable.
    """
    if not ts:
        return datetime.now(timezone.utc)
    try:
        value = ts.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        value = _FRACTION.sub(r"\1", value)
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


# Backwards-compatible alias used by the Linux rule modules.
_parse_timestamp = parse_timestamp


def parse_event_time(event: Event) -> datetime:
    return parse_timestamp(event.timestamp)


class Engine:
    """Detection engine with dedupe and threshold windows.

    All time-based logic (windows AND dedupe) runs on EVENT time, never the wall
    clock, so replaying an old log gives the same result as seeing it live.
    """

    def __init__(self, retain_alerts: bool = True):
        # retain_alerts=False is replay mode (like AlphaSentinel.ps1 -ReplayPath): alerts are
        # returned but not kept, so a repeat inside the dedupe window has no open alert to
        # fold into and fires fresh - which is exactly what the PowerShell replay does.
        self.retain_alerts = retain_alerts
        self._lock = threading.RLock()
        self.windows: Dict[str, List[Dict[str, Any]]] = {}
        self.alerts: List[Alert] = []
        self._by_id: Dict[int, Alert] = {}
        self.next_alert_id = 1
        self.recent_alert_times: Dict[str, datetime] = {}
        self.dedupe_alert_id: Dict[str, int] = {}
        self.current_event: Optional[Event] = None
        self.current_time: Optional[datetime] = None  # event time of the event being evaluated
        self.last_event_time: datetime = datetime.now(timezone.utc)
        self.events_seen = 0
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.recent_events: deque = deque(maxlen=500)
        self.rules_fired: Dict[str, int] = {}
        self.rules_last: Dict[str, str] = {}
        self.hourly: Dict[str, Dict[str, Any]] = {}

    # ---- time -------------------------------------------------------------
    def _now(self) -> datetime:
        return self.current_time or datetime.now(timezone.utc)

    def begin_event(self, event: Event) -> datetime:
        """Called once per event before rule evaluation."""
        with self._lock:
            self.current_event = event
            self.current_time = parse_event_time(event)
            self.last_event_time = self.current_time
            self.events_seen += 1
            host = event.hostname or "unknown"
            h = self.hosts.setdefault(host, {"host": host, "events": 0, "alerts": 0})
            h["events"] += 1
            h["lastSeen"] = self.current_time.isoformat()
            who = event.accountName or event.targetUserName or event.subjectUserName or event.sourceIp or ""
            summary = f"Event {event.eventId}" + (f" - {who}" if who else "")
            self.recent_events.append({
                "time": self.current_time.isoformat(), "eventId": str(event.eventId),
                "host": host, "user": event.accountName or "",
                "sourceIp": event.sourceIp or "", "channel": event.channel,
                "summary": summary[:120], "matchedRule": "",
            })
            hour = self.current_time.strftime("%Y-%m-%dT%H")
            b = self.hourly.setdefault(hour, {"hour": hour, "events": 0, "alerts": 0})
            b["events"] += 1
            if len(self.hourly) > 48:
                del self.hourly[sorted(self.hourly)[0]]
            return self.current_time

    # ---- windows ----------------------------------------------------------
    def add_window_hit(self, rule_key: str, bucket: str, value: Any, minutes: int,
                       event_time: datetime) -> List[Dict[str, Any]]:
        """Add a hit to the rolling window and return the updated window."""
        key = f"{rule_key}|{bucket}"
        hits = self.windows.setdefault(key, [])
        hits.append({"value": value, "time": event_time})
        cutoff = event_time - timedelta(minutes=minutes)
        hits = [h for h in hits if h["time"] > cutoff]
        self.windows[key] = hits
        return hits

    def get_distinct_count(self, items: List[Dict[str, Any]]) -> int:
        seen = {str(item["value"]).lower() for item in items if item["value"]}
        return len(seen)

    # ---- dedupe -----------------------------------------------------------
    def should_dedupe(self, rule_key: str, entity: str, minutes: int = 15,
                      new_severity: Optional[str] = None,
                      new_description: Optional[str] = None) -> bool:
        """True when this hit must NOT create a new alert (PowerShell parity).

        Inside the dedupe window a repeat is suppressed, but it is not lost: it is
        folded into the open alert (Count, LastSeen, contributing events) and, if
        the detection got MORE severe, the open alert is upgraded in place - a
        rising attack must not stay filed at its earlier severity. When the earlier
        alert was acknowledged / resolved (or is gone), a fresh alert is allowed.
        The window length comes from the rule catalog, so both ports agree.
        """
        meta_minutes = WINDOWS_RULE_META.get(rule_key, {}).get("dedupe_minutes")
        if meta_minutes:
            minutes = meta_minutes
        key = f"{rule_key}|{entity if entity else ''}"
        last = self.recent_alert_times.get(key)
        if last is None or abs(self._now() - last) >= timedelta(minutes=minutes):
            return False

        open_alert = self._by_id.get(self.dedupe_alert_id.get(key, -1))
        if open_alert is None or open_alert.Acknowledged or open_alert.Status not in ("New", "Investigating", ""):
            # nothing open to fold the hit into: let a new alert fire
            return False

        target = new_severity or WINDOWS_RULE_META.get(rule_key, {}).get("severity")
        with self._lock:
            if target and SEVERITY_ORDER.get(target, 0) > SEVERITY_ORDER.get(open_alert.Severity, 0):
                open_alert.Severity = target
                if new_description:
                    open_alert.Description = new_description
            now = self._now().isoformat()
            open_alert.LastSeen = now
            open_alert.Count += 1
            ev = self.current_event
            open_alert.Events.append({"time": now, "summary": (
                f"Event {ev.eventId} on {ev.hostname}" if ev else "Repeat hit")})
            if len(open_alert.Events) > MAX_ALERT_EVENTS:
                del open_alert.Events[: len(open_alert.Events) - MAX_ALERT_EVENTS]
        return True

    # ---- alerts -----------------------------------------------------------
    @staticmethod
    def _meta(rule_key: str) -> Dict[str, Any]:
        return WINDOWS_RULE_META.get(rule_key) or LINUX_RULE_META.get(rule_key) or {}

    def new_alert(self, rule_key: str, description: str, severity: Optional[str], event: Event,
                  dedupe_key: Optional[str], event_time: datetime,
                  account_override: Optional[str] = None, entity: str = "") -> Alert:
        meta = self._meta(rule_key)
        sev = severity or meta.get("severity") or "Medium"
        mitre_id = meta.get("mitre_id", "")
        mitre_name = meta.get("mitre_name", "")
        ts = event_time.isoformat()
        with self._lock:
            alert = Alert(
                Id=self.next_alert_id,
                Time=ts,
                RuleKey=rule_key,
                Rule=meta.get("title") or rule_key,
                Severity=sev,
                Title=meta.get("title") or f"Rule {rule_key}",
                Mitre=f"{mitre_id} - {mitre_name}" if mitre_id and mitre_name else mitre_id,
                Remediation=meta.get("remediation") or "Investigate the affected host and account.",
                Description=description,
                Host=event.hostname,
                Account=account_override if account_override is not None else (event.accountName or ""),
                SourceIp=event.sourceIp or "",
                EventId=event.eventId,
                FirstSeen=ts,
                LastSeen=ts,
                Events=[{"time": ts, "summary": f"Event {event.eventId} on {event.hostname}"}],
                DedupeKey=dedupe_key or "",
                MitreId=mitre_id,
                MitreName=mitre_name,
                Tactic=meta.get("category", ""),
                Entity=entity,
            )
            if self.retain_alerts:
                self.alerts.append(alert)
                self._by_id[alert.Id] = alert
            self.next_alert_id += 1
            self.rules_fired[rule_key] = self.rules_fired.get(rule_key, 0) + 1
            self.rules_last[rule_key] = ts
            if self.recent_events and self.current_time and self.recent_events[-1]["time"] == self.current_time.isoformat():
                self.recent_events[-1]["matchedRule"] = rule_key
            hb = self.hourly.get(event_time.strftime("%Y-%m-%dT%H"))
            if hb:
                hb["alerts"] += 1
            h = self.hosts.get(event.hostname or "unknown")
            if h:
                h["alerts"] += 1
            if dedupe_key:
                self.recent_alert_times[dedupe_key] = event_time
                self.dedupe_alert_id[dedupe_key] = alert.Id
            if self.retain_alerts and len(self.alerts) > MAX_ALERTS:
                for old in self.alerts[: len(self.alerts) - MAX_ALERTS]:
                    self._by_id.pop(old.Id, None)
                del self.alerts[: len(self.alerts) - MAX_ALERTS]
            return alert

    def add_external_alert(self, data: Dict[str, Any]) -> Alert:
        """Store an alert forwarded from a remote collector (gets a local Id)."""
        import dataclasses
        allowed = {f.name for f in dataclasses.fields(Alert)} - {"Id"}
        clean = {k: v for k, v in data.items() if k in allowed}
        for req in ("Time", "RuleKey", "Rule", "Severity", "Title", "Mitre", "Remediation",
                    "Description", "Host", "Account", "SourceIp", "EventId"):
            clean.setdefault(req, "")
        if clean.get("Severity") not in SEVERITY_ORDER:
            clean["Severity"] = "Medium"
        with self._lock:
            alert = Alert(Id=self.next_alert_id, **clean)
            self.alerts.append(alert)
            self._by_id[alert.Id] = alert
            self.next_alert_id += 1
            self.rules_fired[alert.RuleKey] = self.rules_fired.get(alert.RuleKey, 0) + 1
            self.rules_last[alert.RuleKey] = alert.Time
            return alert

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        return self._by_id.get(alert_id)

    # ---- evaluation -------------------------------------------------------
    def evaluate(self, event: Event) -> Optional[Alert]:
        """Evaluate one event against all rules. Returns the alert if one fires.

        Errors are NOT swallowed here: a rule that crashes must be visible.
        (The router logs and continues per evaluator, so one broken rule cannot
        stop the others.)
        """
        from alpha_sentinel.rules import evaluate_event as rule_evaluator
        return rule_evaluator(self, event)


def evaluate_event(engine: Engine, event: Event) -> Optional[Alert]:
    """Convenience wrapper kept for backwards compatibility."""
    return engine.evaluate(event)
