"""Anti-forensics / defense-evasion rules ported from AlphaSentinel.ps1.

1102 log cleared, 4719 audit policy changed, 4946-4949 firewall rule changes,
5001/5010/5012 Defender disabled, 4616 system time changed.
"""

from typing import Optional

from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Alert, Event


def evaluate_1102(engine: Engine, event: Event) -> Optional[Alert]:
    """The Security event log was cleared."""
    t = parse_event_time(event)
    if engine.should_dedupe('log_tampering', '', 60):
        return None
    desc = f"The Security event log was cleared on {event.hostname}."
    return engine.new_alert('log_tampering', desc, None, event, 'log_tampering|', t)


def evaluate_4719(engine: Engine, event: Event) -> Optional[Alert]:
    """System audit policy was changed."""
    t = parse_event_time(event)
    ent = (event.subcategory or "").lower()
    if engine.should_dedupe('audit_policy_changed', ent, 60):
        return None
    desc = (f"The system audit policy was changed on {event.hostname} by "
            f"\"{event.subjectUserName or ''}\" - audit subcategory \"{event.subcategory or ''}\".")
    return engine.new_alert('audit_policy_changed', desc, None, event, f'audit_policy_changed|{ent}', t)


def evaluate_4946_4947_4948_4949(engine: Engine, event: Event) -> Optional[Alert]:
    """A Windows Firewall rule was added / modified / deleted."""
    t = parse_event_time(event)
    ent = (event.ruleName or "").lower()
    if engine.should_dedupe('firewall_rule_modified', ent, 15):
        return None
    action = {'4946': 'added', '4948': 'deleted'}.get(str(event.eventId), 'modified')
    desc = (f"A Windows Firewall rule was {action} on {event.hostname} by "
            f"\"{event.subjectUserName or ''}\" - rule \"{event.ruleName or ''}\".")
    return engine.new_alert('firewall_rule_modified', desc, None, event, f'firewall_rule_modified|{ent}', t)


def evaluate_5001_5010_5012(engine: Engine, event: Event) -> Optional[Alert]:
    """Windows Defender real-time protection / scanning disabled."""
    t = parse_event_time(event)
    if engine.should_dedupe('defender_disabled', '', 60):
        return None
    label = {'5001': 'real-time protection', '5010': 'on-access scanning'}.get(
        str(event.eventId), 'antivirus scanning')
    desc = f"Windows Defender {label} was disabled on {event.hostname}."
    return engine.new_alert('defender_disabled', desc, None, event, 'defender_disabled|', t)


def evaluate_4616(engine: Engine, event: Event) -> Optional[Alert]:
    """The system time was changed (breaks Kerberos and log correlation)."""
    t = parse_event_time(event)
    if engine.should_dedupe('system_time_changed', '', 15):
        return None
    to = f" to {event.newTime}" if event.newTime else ""
    desc = (f"The system time was changed on {event.hostname} by "
            f"\"{event.subjectUserName or ''}\"{to} - breaks Kerberos and log correlation.")
    return engine.new_alert('system_time_changed', desc, None, event, 'system_time_changed|', t)
