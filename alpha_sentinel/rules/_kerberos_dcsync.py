"""Kerberoasting / DCSync / LDAP recon detection."""

from typing import Optional
from alpha_sentinel.engine import Engine, parse_event_time
from alpha_sentinel.models import Event, Alert
from datetime import datetime, timezone


def evaluate_4769(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4769 (Kerberos Service Ticket Request) for Kerberoasting.
    
    TicketEncryptionType 0x17 (RC4-HMAC) on a SUCCESSFUL request for a
    user-owned service principal is the Kerberoasting signal. Excluded:
    failed requests, machine SPNs (HOST/PC01$), krbtgt, and requests coming
    from machine accounts.
    """
    enc = (event.encryptionType or "").lower()
    svc = event.serviceName or ""
    account = event.accountName or ""
    status = event.statusCode or event.status or ""
    
    is_rc4 = enc in ('0x17', '23', '17')
    is_failure = status and status not in ('0x0', '0', '0x00000000', '')
    
    evt_time = parse_event_time(event)
    
    # Exclude: failed requests, machine SPNs (HOST/...), krbtgt, machine accounts
    svc_lower = svc.lower()
    is_krbtgt = 'krbtgt' in svc_lower
    is_machine_spn = svc_lower.startswith('host/') and svc_lower.endswith('$')
    is_machine_account = account.endswith('$')
    
    if is_rc4 and not is_failure and svc and not is_krbtgt and not is_machine_spn and not is_machine_account:
        # Track distinct SPNs per requesting account
        hits = engine.add_window_hit('kerb', account, svc, 10, evt_time)
        distinct_spn = engine.get_distinct_count(hits)
        
        # Single RC4 = Medium, 3+ distinct SPNs = High (escalates)
        sev = 'High' if distinct_spn >= 3 else 'Medium'
        desc = f"Service ticket requested for \"{svc}\" using weak RC4 encryption (0x17) - requesting account \"{account}\"."
        if distinct_spn > 1:
            desc += f" {distinct_spn} distinct service principals requested in the last 10 minutes."
        
        if not engine.should_dedupe('kerberoasting', account, 15, sev, desc):
            return engine.new_alert('kerberoasting', desc, sev, event, f'kerberoasting|{account}', evt_time)
    
    return None


def evaluate_4662(engine: Engine, event: Event) -> Optional[Alert]:
    """Evaluate Event 4662/5141 for DCSync replication and LDAP recon.
    
    The replication GUIDs live in Properties, so search the whole record
    (Properties + ObjectType + ObjectName) rather than ObjectType alone.
    """
    hay = " ".join(filter(None, [
        event.properties or "",
        event.objectType or "",
        event.objectName or ""
    ])).lower()
    
    # DCSync replication GUIDs
    replication_guids = [
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
        '89e95b76-444d-4c62-991a-0facbeda640c'
    ]
    
    hit_guid = None
    for g in replication_guids:
        if g in hay:
            hit_guid = g
            break
    
    subject = event.subjectUserName or ""
    
    evt_time = parse_event_time(event)
    
    if hit_guid:
        # DC replicates as machine account (DC01$) - that's normal
        if not subject.endswith('$'):
            mask_note = f" (access mask {event.accessMask})" if event.accessMask else ""
            desc = f"Account \"{subject}\" used directory replication rights (right {hit_guid}{mask_note}, object \"{event.objectName or ''}\") - DCSync credential dumping."
            
            if not engine.should_dedupe('dcsync_replication', subject, 15):
                return engine.new_alert('dcsync_replication', desc, 'Critical', event, f'dcsync_replication|{subject}', evt_time)
    
    else:
        # LDAP recon heuristic: many object reads by one principal
        bucket = event.sourceIp or event.subjectUserName or ""
        obj_type = (event.objectType or "").lower()
        type_ok = not obj_type or any(t in obj_type for t in ['user', 'group', 'computer', 'domain', 'contact', 'organizational']) or len(obj_type) == 36
        
        if bucket and type_ok and not bucket.endswith('$'):
            hits = engine.add_window_hit('ldap', bucket, event.objectName or "", 5, evt_time)
            if hits and len(hits) >= 25:
                desc = f"{len(hits)} directory object reads (e.g. \"{event.objectName or ''}\") by \"{bucket}\" within 5 minutes - domain enumeration pattern."
                
                if not engine.should_dedupe('ldap_recon', bucket, 30):
                    return engine.new_alert('ldap_recon', desc, 'Medium', event, f'ldap_recon|{bucket}', evt_time)
    
    return None