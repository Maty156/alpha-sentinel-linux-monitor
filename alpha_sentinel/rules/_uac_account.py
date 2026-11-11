"""Account control / enable/disable / password reset / DSRM detection."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4738(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4738 (Account Control Changed).
    
    Compare WHAT CHANGED (new AND NOT old). Only flags that actually changed trigger.
    Risky transitions: pre-auth not required (AS-REP roastable), password not required,
    delegation granted, account re-enabled.
    """
    account = event.accountName or event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    evt_time = parse_event_time(event)
    
    old_val = event.oldUserAccountControl or ""
    new_val = event.newUserAccountControl or ""
    
    # Parse UAC flags (hex strings like "0x200")
    def parse_uac(val: str) -> int:
        if not val:
            return 0
        val = val.strip()
        if val.lower().startswith('0x'):
            return int(val, 16)
        try:
            return int(val)
        except ValueError:
            return 0
    
    old_flags = parse_uac(old_val)
    new_flags = parse_uac(new_val)
    
    if new_flags == 0:
        return None
    
    gained = new_flags & (~old_flags)
    lost = old_flags & (~new_flags)
    
    problems = []
    # 0x400000 = DONT_REQ_PREAUTH (AS-REP roastable) - Critical
    if gained & 0x400000:
        problems.append('Kerberos pre-authentication is no longer required (AS-REP roastable)')
    # 0x20 = PASSWD_NOTREQD - High
    if gained & 0x20:
        problems.append('a password is no longer required')
    # 0x80000 = TRUSTED_FOR_DELEGATION (unconstrained) - High
    if gained & 0x80000:
        problems.append('unconstrained Kerberos delegation was granted')
    # 0x1000000 = TRUSTED_TO_AUTH_FOR_DELEGATION (constrained with protocol transition) - High
    if gained & 0x1000000:
        problems.append('constrained delegation with protocol transition was granted')
    # 0x2 = ACCOUNTDISABLE cleared (re-enabled) - High
    if lost & 0x2:
        problems.append('the account was re-enabled')
    
    if not problems:
        return None
    
    # Severity: Critical if pre-auth disabled, else High
    sev = 'Critical' if (gained & 0x400000) else 'High'
    
    # Deduped per account
    if not engine.should_dedupe('account_control_changed', account, sev, '; '.join(problems)):
        desc = f"Account \"{account}\" was changed by \"{subject}\" - {'; '.join(problems)}."
        return engine.new_alert('account_control_changed', desc, sev, event, f'account_control_changed|{account}', evt_time)
    
    return None


def evaluate_4722(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4722 (Account Enabled)."""
    account = event.accountName or event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    # Skip computer accounts
    if account.endswith('$'):
        return None
    
    evt_time = parse_event_time(event)
    
    if not engine.should_dedupe('account_enabled_disabled', account):
        desc = f"Account \"{account}\" was enabled by \"{subject}\"."
        return engine.new_alert('account_enabled_disabled', desc, 'Medium', event, f'account_enabled_disabled|{account}', evt_time)
    
    return None


def evaluate_4725(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4725 (Account Disabled)."""
    account = event.accountName or event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    # Skip computer accounts
    if account.endswith('$'):
        return None
    
    evt_time = parse_event_time(event)
    
    if not engine.should_dedupe('account_enabled_disabled', account):
        desc = f"Account \"{account}\" was disabled by \"{subject}\"."
        return engine.new_alert('account_enabled_disabled', desc, 'Medium', event, f'account_enabled_disabled|{account}', evt_time)
    
    return None


def evaluate_4724(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4724 (Password Reset by Admin)."""
    account = event.accountName or event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    evt_time = parse_event_time(event)
    
    if not engine.should_dedupe('password_reset_by_admin', account):
        desc = f"Administrator \"{subject}\" reset the password for account \"{account}\"."
        return engine.new_alert('password_reset_by_admin', desc, 'Medium', event, f'password_reset_by_admin|{account}', evt_time)
    
    return None


def evaluate_4726(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4726 (Account Deleted)."""
    account = event.accountName or event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    evt_time = parse_event_time(event)
    
    if not engine.should_dedupe('account_deleted', account):
        desc = f"Account \"{account}\" was deleted by \"{subject}\"."
        return engine.new_alert('account_deleted', desc, 'Medium', event, f'account_deleted|{account}', evt_time)
    
    return None


def evaluate_4794(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4794 (DSRM Password Set) - always Critical on DC."""
    account = event.accountName or event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    # Skip machine accounts
    if subject.endswith('$'):
        return None
    
    evt_time = parse_event_time(event)
    
    sev = 'Critical'
    desc = f"DSRM password was changed on Domain Controller \"{account}\" by \"{subject}\" - this is a critical compromise indicator."
    ent = f"{account}|{subject}"
    
    if not engine.should_dedupe('dsrm_password_set', ent, sev, desc):
        return engine.new_alert('dsrm_password_set', desc, sev, event, f'dsrm_password_set|{ent}', evt_time)
    
    return None