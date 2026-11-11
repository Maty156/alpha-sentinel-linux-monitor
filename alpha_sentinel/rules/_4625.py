"""Password spraying / brute force / NTLM failed auth detection."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4625(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4625 (Failed Logon) for password spraying and brute force."""
    account = event.accountName
    src_ip = event.sourceIp
    
    # Parse event timestamp
    evt_time = parse_event_time(event)
    
    if src_ip and src_ip != '-':
        # Track spray hits per source IP
        hits = engine.add_window_hit('password_spraying', src_ip, account, 10, evt_time)
        distinct = engine.get_distinct_count(hits)
        
        if distinct >= 5 and not engine.should_dedupe('password_spraying', src_ip):
            desc = f"{distinct} distinct accounts failed to authenticate from {src_ip} within 10 minutes."
            return engine.new_alert('password_spraying', desc, 'High', event, f'password_spraying|{src_ip}', evt_time)
    
    # Track brute force against single account
    if account:
        brute_hits = engine.add_window_hit('brute', account, account, 10, evt_time)
        if brute_hits and len(brute_hits) >= 8 and not engine.should_dedupe('brute_force_single_account', account):
            sev = 'High' if len(brute_hits) >= 20 else 'Medium'
            desc = f"{len(brute_hits)} failed logon attempts against account \"{account}\" within 10 minutes."
            return engine.new_alert('brute_force_single_account', desc, sev, event, f'brute_force_single_account|{account}', evt_time)
    
    return None


def evaluate_4771(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4771 (Kerberos Pre-Authentication Failed) for spraying."""
    account = event.accountName
    src_ip = event.sourceIp
    
    evt_time = parse_event_time(event)
    
    if src_ip and src_ip != '-':
        hits = engine.add_window_hit('kerberos_preauth_spraying', src_ip, account, 10, evt_time)
        distinct = engine.get_distinct_count(hits)
        
        if distinct >= 5 and not engine.should_dedupe('kerberos_preauth_spraying', src_ip):
            desc = f"{distinct} distinct accounts failed Kerberos pre-authentication from {src_ip} within 10 minutes - Kerberos-side password spraying."
            return engine.new_alert('kerberos_preauth_spraying', desc, 'High', event, f'kerberos_preauth_spraying|{src_ip}', evt_time)
    
    return None


def evaluate_4776(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4776 (NTLM Credential Validation) for failed auth bursts."""
    account = event.accountName
    status = event.statusCode or event.status or ""
    workstation = event.workstationName or ""
    src_ip = event.sourceIp or ""
    
    evt_time = parse_event_time(event)
    
    # Check if success (0x0 or 0)
    is_success = status.lower() in ('0x0', '0', '0x00000000')
    
    # Bucket is workstationName or sourceIp
    bucket = workstation if workstation else src_ip
    
    if not is_success and bucket:
        hits = engine.add_window_hit('ntlm_failed_auth', bucket, account, 10, evt_time)
        if hits and len(hits) >= 8 and not engine.should_dedupe('ntlm_failed_auth', bucket):
            desc = f"{len(hits)} NTLM credential validation failures from workstation \"{bucket}\" within 10 minutes."
            return engine.new_alert('ntlm_failed_auth', desc, 'High', event, f'ntlm_failed_auth|{bucket}', evt_time)
    
    return None