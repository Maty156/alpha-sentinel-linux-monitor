"""Logon events (4624) - suspicious remote logon, pass-the-hash, anonymous SMB."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4624(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4624 (Logon) for multiple rules:
    - anonymous_smb_session (type 3, no credentials)
    - pass_the_hash_logon (type 9 or type 3 with NTLM KeyLength=0)
    - suspicious_remote_logon (type 10 RDP or type 3 admin network logon)
    """
    logon_type = event.logonType or ""
    account = event.accountName or event.targetUserName or ""
    src_ip = event.sourceIp or ""
    auth_pkg = event.authenticationPackageName or ""
    key_len = event.keyLength or ""
    target_sid = event.targetUserSid or ""
    
    evt_time = parse_event_time(event)
    
    # 1. Anonymous SMB session - type 3 with no credentials (ANONYMOUS LOGON / null session)
    if logon_type == '3':
        anon = (not account or account == 'ANONYMOUS LOGON' or target_sid == 'S-1-5-7')
        if anon and src_ip and src_ip not in ('-', '::1', '127.0.0.1'):
            # Deduped per source IP per hour
            if not engine.should_dedupe('anonymous_smb_session', src_ip, 60):
                desc = f"A null (anonymous) SMB session from {src_ip} - pre-auth enumeration (RID cycling, SID brute-forcing, null-session tooling) starts like this."
                return engine.new_alert('anonymous_smb_session', desc, 'Medium', event, f'anonymous_smb_session|{src_ip}', evt_time)
    
    # 2. Pass-the-hash: LogonType 9 (new credentials) OR LogonType 3 with NTLM and KeyLength=0
    is_pth = (logon_type == '9') or (logon_type == '3' and auth_pkg.upper() == 'NTLM' and key_len == '0')
    if is_pth and account and not account.endswith('$') and src_ip and src_ip not in ('-', '::1', '127.0.0.1'):
        ent = f"{account}|{src_ip}"
        desc = f'Pass-the-hash logon (type {logon_type}) by \"{account}\" from {src_ip} - NTLM KeyLength=0 indicates credential reuse.'
        if not engine.should_dedupe('pass_the_hash_logon', ent, 15):
            return engine.new_alert('pass_the_hash_logon', desc, 'Critical', event, f'pass_the_hash_logon|{ent}', evt_time)
    
    # 3. Suspicious remote logon
    # Type 10 (RDP) is interesting for any human account
    # Type 3 (network) only interesting for non-service accounts with admin-style names
    is_rdp = (logon_type == '10')
    
    # Service account patterns to exclude
    service_patterns = ['svc', 'service', 'app', 'sql', 'backup', 'sccm', 'vss', 'mssql', 'web', 'job', 'task', 
                        'nagios', 'zabbix', 'splunk', 'veeam', 'commvault']
    is_service_like = any(pattern in account.lower() for pattern in service_patterns) or \
                      any(account.lower().endswith(f'_{p}') or account.lower().endswith(f'-{p}') for p in service_patterns)
    
    # Admin-style names
    admin_patterns = ['admin', 'da_', 'root', 'administrator']
    is_admin_name = any(pattern in account.lower() for pattern in admin_patterns)
    
    is_network_admin = (logon_type == '3') and (not is_service_like) and is_admin_name
    
    if (is_rdp or is_network_admin) and account and not account.endswith('$'):
        # System accounts to exclude
        system_accounts = ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
        if account.upper() not in system_accounts:
            ent = f"{account}|{src_ip}"
            sev = 'High' if (is_rdp and not is_service_like and is_admin_name) else 'Medium'
            kind = 'Remote desktop' if is_rdp else 'Administrative network'
            desc = f"{kind} logon (type {logon_type}) by \"{account}\" from {src_ip}."
            
            if not engine.should_dedupe('suspicious_remote_logon', ent, 15, sev, desc):
                return engine.new_alert('suspicious_remote_logon', desc, sev, event, f'suspicious_remote_logon|{ent}', evt_time)
    
    return None