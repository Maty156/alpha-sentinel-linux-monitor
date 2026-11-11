"""AS-REP roasting / DSRM / Event log / Firewall / Process / PS Scriptblock detection."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4768(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4768 (Kerberos TGT Request) for AS-REP roasting.
    
    PreAuthType 0 = this account does not require Kerberos pre-auth, so the
    TGT comes back encrypted with the password hash. A SINGLE one is enough.
    """
    account = event.accountName or event.targetUserName or ""
    status = event.statusCode or event.status or ""
    preauth = event.preAuthType or ""
    
    # Success: status is 0x0 or 0 or empty
    ok = (not status) or status in ('0x0', '0', '0x00000000')
    
    evt_time = parse_event_time(event)
    
    if preauth == '0' and ok and account and not account.endswith('$'):
        hits = engine.add_window_hit('asrep', account, account, 10, evt_time)
        sev = 'Critical' if hits and len(hits) >= 5 else 'High'
        desc = f"TGT issued for account \"{account}\" which does not require Kerberos pre-authentication (AS-REP roastable) - {len(hits)} request(s) in 10 minutes."
        
        if not engine.should_dedupe('asrep_roasting', account, sev, desc):
            return engine.new_alert('asrep_roasting', desc, sev, event, f'asrep_roasting|{account}', evt_time)
    
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


def evaluate_1100(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 1100 (Event Log Service Stopped)."""
    evt_time = parse_event_time(event)
    
    # Global dedupe
    if not engine.should_dedupe('eventlog_service_stopped', None):
        desc = f"The Windows Event Log service stopped on {event.hostname} - auditing is blind until it restarts."
        return engine.new_alert('eventlog_service_stopped', desc, 'Medium', event, 'eventlog_service_stopped|global', evt_time)
    
    return None


def evaluate_4950(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4950 (Firewall Profile Disabled).
    
    A WHOLE PROFILE being turned off: SettingType EnableFirewall with value
    'No' (some builds write 'Enable Windows Firewall', the oldest write '0').
    """
    setting_type = event.settingType or ""
    setting_value = event.settingValue or ""
    profile = event.profileChanged or ""
    subject = event.subjectUserName or ""
    
    evt_time = parse_event_time(event)
    
    is_enable_firewall = setting_type in ('EnableFirewall', 'Enable Windows Firewall')
    is_off = setting_value in ('No', '0', 'False')
    
    if is_enable_firewall and is_off:
        if not engine.should_dedupe('firewall_disabled', profile):
            desc = f"The Windows Firewall '{profile}' profile was turned OFF on {event.hostname} by \"{subject}\" - the host is open for lateral movement."
            # Account left empty to match PS oracle
            return engine.new_alert('firewall_disabled', desc, 'Critical', event, f'firewall_disabled|{profile}', evt_time, account_override="")
    
    return None


def evaluate_4688(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4688 (Process Creation) - detect suspicious command lines.
    
    Only fires when command-line logging is enabled (ProcessCreationIncludeCmdLine_Enabled=1).
    Patterns: ntdsutil, vssadmin delete/create shadow, reg save SAM/SYSTEM/SECURITY,
    rundll32 comsvcs.dll MiniDump, certutil -urlcache, encoded PowerShell (-enc).
    """
    cmd = event.commandLine or ""
    if not cmd:
        return None  # command-line logging not enabled or empty
    
    cmd_lower = cmd.lower()
    is_suspicious = False
    matched_pattern = ''
    
    if 'ntdsutil' in cmd_lower:
        is_suspicious = True
        matched_pattern = 'ntdsutil'
    elif 'vssadmin' in cmd_lower and ('delete' in cmd_lower or 'create' in cmd_lower) and 'shadow' in cmd_lower:
        is_suspicious = True
        matched_pattern = 'vssadmin shadow copy abuse'
    elif 'reg' in cmd_lower and 'save' in cmd_lower and any(hive in cmd_lower for hive in ['sam', 'system', 'security']):
        is_suspicious = True
        matched_pattern = 'reg save of hive'
    elif 'rundll32' in cmd_lower and 'comsvcs.dll' in cmd_lower and 'minidump' in cmd_lower:
        is_suspicious = True
        matched_pattern = 'rundll32 comsvcs.dll MiniDump (LSASS dump)'
    elif 'certutil' in cmd_lower and any(flag in cmd_lower for flag in ['-urlcache', '-verifyctl', '-encode', '-decode']):
        is_suspicious = True
        matched_pattern = 'certutil -urlcache/verifyctl/encode/decode'
    elif '-enc' in cmd_lower:
        is_suspicious = True
        matched_pattern = 'encoded PowerShell (-enc)'
    elif 'powershell' in cmd_lower and any(flag in cmd_lower for flag in ['-enc', '-encodedcommand']):
        is_suspicious = True
        matched_pattern = 'encoded PowerShell (-encodedCommand)'
    
    if not is_suspicious:
        return None
    
    account = event.accountName or event.subjectUserName or ""
    subject = event.subjectUserName or ""
    new_proc = event.newProcessName or ""
    
    # Skip system accounts
    system_accounts = ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
    if subject in system_accounts:
        return None
    
    evt_time = parse_event_time(event)
    
    desc = f"Suspicious process creation by \"{subject}\" (\"{account}\"): {new_proc} {cmd} [matched: {matched_pattern}]"
    ent = f"{account}|{matched_pattern}"
    
    if not engine.should_dedupe('suspicious_process_creation', ent):
        return engine.new_alert('suspicious_process_creation', desc, 'High', event, f'suspicious_process_creation|{ent}', evt_time)
    
    return None


def evaluate_4104(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4104 (PowerShell Script Block Logging) - detect offensive content.
    
    Requires: GPO "Turn on PowerShell Script Block Logging" enabled.
    Matches known offensive strings in script block text (truncated for storage).
    """
    script_text = event.scriptBlockText or ""
    if not script_text:
        return None
    
    text = script_text.lower()
    is_malicious = False
    matched_pattern = ''
    
    patterns = [
        ('invoke-mimikatz', 'Invoke-Mimikatz'),
        ('dumpcreds', 'DumpCreds'),
        ('invoke-kerberoast', 'Invoke-Kerberoast'),
        ('frombase64string.*iex', 'FromBase64String + IEX'),
        ('amsiutils', 'AmsiUtils (AMSI bypass)'),
        ('invoke-obfuscation', 'Invoke-Obfuscation'),
        ('invoke-expression.*obfuscat', 'Invoke-Expression with obfuscation'),
        (r'iex\s*\(.*frombase64string', 'IEX(FromBase64String)'),
        (r'system\.net\.webclient.*downloadstring', 'WebClient.DownloadString'),
        (r'start-process.*-windowstyle\s*hidden', 'Start-Process -WindowStyle Hidden'),
    ]
    
    for pattern, name in patterns:
        import re
        if re.search(pattern, text):
            is_malicious = True
            matched_pattern = name
            break
    
    if not is_malicious:
        return None
    
    account = event.accountName or event.subjectUserName or ""
    subject = event.subjectUserName or ""
    hostname = event.hostname or ""
    
    # Skip system accounts
    system_accounts = ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
    if subject in system_accounts:
        return None
    
    evt_time = parse_event_time(event)
    
    # Truncate stored script text to 500 chars for safety
    stored_text = script_text[:500] + '... [truncated]' if len(script_text) > 500 else script_text
    
    desc = f"PowerShell script block by \"{subject}\" on \"{hostname}\" matched offensive pattern: {matched_pattern}. Script: {stored_text}"
    ent = f"{account}|{matched_pattern}"
    
    if not engine.should_dedupe('powershell_scriptblock', ent):
        return engine.new_alert('powershell_scriptblock', desc, 'High', event, f'powershell_scriptblock|{ent}', evt_time)
    
    return None