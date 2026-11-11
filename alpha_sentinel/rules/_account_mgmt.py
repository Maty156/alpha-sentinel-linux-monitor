"""Account lockout storm / account created / group membership detection."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4740(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4740 (Account Lockout) for lockout storms."""
    account = event.accountName
    
    evt_time = parse_event_time(event)
    
    # Global dedupe for lockout storms
    hits = engine.add_window_hit('lockout', 'global', account, 10, evt_time)
    distinct = engine.get_distinct_count(hits)
    
    if distinct >= 3 and not engine.should_dedupe('account_lockout_storm', None):
        desc = f"{distinct} distinct accounts were locked out within 10 minutes - consistent with password spraying that crossed the lockout threshold."
        return engine.new_alert('account_lockout_storm', desc, 'High', event, 'account_lockout_storm|global', evt_time)
    
    return None


def evaluate_4720(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4720 (Account Created).
    
    Fires when a new user account is created.
    Skips machine accounts (those ending in $) as they are routine domain joins.
    """
    account = event.accountName or ""
    
    # Skip computer accounts
    if account.endswith('$'):
        return None
    
    evt_time = parse_event_time(event)
    
    if not engine.should_dedupe('account_created', account):
        desc = f"New account \"{account}\" was created."
        return engine.new_alert('account_created', desc, 'High', event, f'account_created|{account}', evt_time)
    
    return None


_PRIVILEGED_GROUPS = [
    'domain admins', 'enterprise admins', 'schema admins', 'administrators',
    'account operators', 'backup operators', 'server operators',
    'print operators', 'group policy creator owners', 'dnsadmins',
    'exchange organization administrators', 'replicator',
]


def evaluate_4729_4733(engine: Engine, event: Event) -> Optional[Alert]:
    """Events 4729/4733: an account was REMOVED from a security group.

    Removal from a privileged group can be an attacker covering their tracks (or
    an admin locking them out), so it is reported too. Deduped per removed account.
    """
    group = event.targetGroup or event.targetUserName or ""
    who = event.memberName or event.accountName or ""
    if not group or not who:
        return None
    if not any(pg in group.lower() for pg in _PRIVILEGED_GROUPS):
        return None
    evt_time = parse_event_time(event)
    if engine.should_dedupe('group_membership_removed', who):
        return None
    desc = (f"Account \"{who}\" was removed from privileged group \"{group}\" "
            f"by \"{event.subjectUserName or ''}\".")
    return engine.new_alert('group_membership_removed', desc, None, event,
                            f'group_membership_removed|{who}', evt_time)


def evaluate_4728_4732_4756(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Events 4728/4732/4756 (Group Membership changes).
    
    These fire when an account is added to a privileged group (Domain Admins, etc.).
    Dedupe is per added ACCOUNT - the account that was added to the group.
    """
    target_group = event.targetUserName or event.targetGroup or ""
    account = event.memberName or event.accountName or ""
    subject = event.subjectUserName or ""
    
    # Check if this involves a privileged group
    privileged_groups = [
        'domain admins', 'enterprise admins', 'schema admins', 'administrators',
        'account operators', 'backup operators', 'server operators',
        'print operators', 'group policy creator owners', 'dnsadmins',
        'exchange organization administrators', 'replicator'
    ]
    
    if not target_group or not account:
        return None
    
    target_lower = target_group.lower()
    is_privileged = any(pg in target_lower for pg in privileged_groups)
    
    if not is_privileged:
        return None
    
    # Deduped per added account - use the account being added (memberName)
    who = account  # The account that was added
    
    if not who:
        return None
    
    evt_time = parse_event_time(event)
    
    if not engine.should_dedupe('privilege_escalation', who):
        desc = f"Account \"{who}\" was added to privileged group \"{target_group}\" by \"{subject}\"."
        return engine.new_alert('privilege_escalation', desc, 'Critical', event, f'privilege_escalation|{who}', evt_time)
    
    return None