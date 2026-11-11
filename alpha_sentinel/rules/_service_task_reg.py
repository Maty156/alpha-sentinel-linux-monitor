"""Explicit credential logon (4648) / Service creation (4697/7045) / Scheduled task (4698) / Registry persistence (4657)."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4648(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4648 (Explicit Credential Use / Logon with Explicit Credentials).
    
    Fires when a process starts with explicitly supplied credentials against a privileged or service account.
    """
    target_user = event.targetUserName or ""
    subject = event.subjectUserName or ""
    
    # Check if target is privileged
    privileged_names = ['admin', 'da_', 'root', 'administrator', 'svc', 'service', 'backup', 'sql', 'krbtgt', 'replicat']
    is_privileged = any(p in target_user.lower() for p in privileged_names)
    
    if not is_privileged:
        return None
    
    evt_time = parse_event_time(event)
    
    ent = f"{subject}|{target_user}"
    extra = f" (process: {event.processName})" if event.processName else ""
    srv = f" on {event.targetServerName}" if event.targetServerName else ""
    
    if not engine.should_dedupe('explicit_credential_logon', ent, 15):
        desc = f"Account \"{subject}\" started a process using explicit credentials for \"{target_user}\"{srv}{extra}."
        return engine.new_alert('explicit_credential_logon', desc, 'Medium', event, f'explicit_credential_logon|{ent}', evt_time)
    
    return None


def evaluate_4697_7045(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Events 4697/7045 (Service Creation/Modification)."""
    path = event.serviceFileName or event.imagePath or ""
    svc_name = event.serviceName or ""
    subject = event.subjectUserName or ""
    
    suspicious_paths = [
        'powershell', 'pwsh', 'cmd.exe', 'wmic', 'mshta', 'rundll32', 'regsvr32',
        'certutil', 'bitsadmin', 'net.exe', '-enc', '/c', '\\temp\\', '\\users\\public\\',
        '\\appdata\\', '\\programdata\\', '\\windows\\tasks'
    ]
    
    is_suspicious = any(p in path.lower() for p in suspicious_paths) if path else False
    sev = 'High' if is_suspicious else 'Medium'
    bin_note = f" (binary: {path})" if path else ""
    sev_note = " with a suspicious binary path" if is_suspicious else ""
    
    evt_time = parse_event_time(event)
    
    desc = f"New service \"{svc_name}\" installed{bin_note}{sev_note}."
    ent = svc_name
    
    if not engine.should_dedupe('service_abuse', ent, 15, sev, desc):
        return engine.new_alert('service_abuse', desc, sev, event, f'service_abuse|{ent}', evt_time)
    
    return None


def evaluate_4698(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4698 (Scheduled Task Created)."""
    task_name = event.taskName or ""
    subject = event.subjectUserName or ""
    cmd = event.commandLine or ""
    
    evt_time = parse_event_time(event)
    
    ent = task_name or subject
    cmd_note = f" (command: {cmd})" if cmd else ""
    
    if not engine.should_dedupe('scheduled_task_created', ent, 15):
        desc = f"Scheduled task \"{task_name}\" was created by \"{subject}\"{cmd_note}."
        return engine.new_alert('scheduled_task_created', desc, 'High', event, f'scheduled_task_created|{ent}', evt_time)
    
    return None


def evaluate_4657(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4657 (Registry Value Modified) for persistence keys."""
    key = event.registryKey or event.objectName or ""
    val_name = event.registryValueName or ""
    subject = event.subjectUserName or ""
    
    persistence_patterns = [
        r'currentversion\\run(once)?',
        r'image file execution options',
        r'\\winlogon\\',
        r'explorer\\user shell folders',
        r'explorer\\shell folders',
        r'\\services\\.+\\parameters',
        r'\\policies\\system\\',
        r'\\lsa\\'
    ]
    
    import re
    is_persist = any(re.search(pattern, key, re.IGNORECASE) for pattern in persistence_patterns)
    
    if not is_persist:
        return None
    
    evt_time = parse_event_time(event)
    
    val_note = f" (value: {val_name})" if val_name else ""
    
    if not engine.should_dedupe('registry_persistence', key, 15):
        desc = f"Registry key \"{key}\" was modified by \"{subject}\"{val_note} - autostart/persistence key."
        return engine.new_alert('registry_persistence', desc, 'High', event, f'registry_persistence|{key}', evt_time)
    
    return None