"""Rules package - one module per rule family, plus the event router.

Windows events are routed by Event ID to a single evaluator; Linux events
(event.osFamily == "linux") go only to the Linux rule set. A rule that raises is
logged with its traceback and skipped - it never stops the other rules and is
never silently swallowed.
"""

import logging
from typing import Callable, Dict, List, Optional

from alpha_sentinel.models import Alert, Event
from alpha_sentinel.rules._4625 import evaluate_4625, evaluate_4771, evaluate_4776
from alpha_sentinel.rules._account_mgmt import (
    evaluate_4720, evaluate_4728_4732_4756, evaluate_4729_4733, evaluate_4740)
from alpha_sentinel.rules._uac_account import (
    evaluate_4722, evaluate_4724, evaluate_4725, evaluate_4726, evaluate_4738, evaluate_4794)
from alpha_sentinel.rules._misc import (
    evaluate_1100, evaluate_4104, evaluate_4688, evaluate_4768, evaluate_4950)
from alpha_sentinel.rules._kerberos_dcsync import evaluate_4662, evaluate_4769
from alpha_sentinel.rules._logon import evaluate_4624
from alpha_sentinel.rules._service_task_reg import (
    evaluate_4648, evaluate_4657, evaluate_4697_7045, evaluate_4698)
from alpha_sentinel.rules._advanced import evaluate_4672, evaluate_4741_4742, evaluate_5136
from alpha_sentinel.rules._evasion import (
    evaluate_1102, evaluate_4616, evaluate_4719, evaluate_4946_4947_4948_4949,
    evaluate_5001_5010_5012)
from alpha_sentinel.rules.linux_ssh import (
    evaluate_root_ssh_login, evaluate_ssh_bruteforce, evaluate_ssh_key_auth,
    evaluate_ssh_success_after_failures)
from alpha_sentinel.rules.linux_system import (
    evaluate_cron_or_systemd_persistence, evaluate_ssh_authorized_keys_modified,
    evaluate_sshd_config_modified, evaluate_sudo_privilege_escalation,
    evaluate_suspicious_command_execution, evaluate_user_account_changed)

log = logging.getLogger("alpha_sentinel.rules")

Evaluator = Callable[..., Optional[Alert]]

WINDOWS_EVALUATORS: Dict[int, Evaluator] = {
    4625: evaluate_4625, 4771: evaluate_4771, 4776: evaluate_4776,
    4740: evaluate_4740,
    4728: evaluate_4728_4732_4756, 4732: evaluate_4728_4732_4756, 4756: evaluate_4728_4732_4756,
    4729: evaluate_4729_4733, 4733: evaluate_4729_4733,
    4720: evaluate_4720, 4738: evaluate_4738, 4722: evaluate_4722, 4725: evaluate_4725,
    4724: evaluate_4724, 4726: evaluate_4726, 4794: evaluate_4794,
    4662: evaluate_4662, 5141: evaluate_4662,
    4624: evaluate_4624, 4648: evaluate_4648,
    4697: evaluate_4697_7045, 7045: evaluate_4697_7045,
    4698: evaluate_4698, 4657: evaluate_4657,
    4946: evaluate_4946_4947_4948_4949, 4947: evaluate_4946_4947_4948_4949,
    4948: evaluate_4946_4947_4948_4949, 4949: evaluate_4946_4947_4948_4949,
    1102: evaluate_1102, 4719: evaluate_4719, 1100: evaluate_1100,
    5001: evaluate_5001_5010_5012, 5010: evaluate_5001_5010_5012, 5012: evaluate_5001_5010_5012,
    4950: evaluate_4950, 4616: evaluate_4616, 4104: evaluate_4104,
    4769: evaluate_4769, 4768: evaluate_4768, 4672: evaluate_4672,
    5136: evaluate_5136, 4741: evaluate_4741_4742, 4742: evaluate_4741_4742,
    4688: evaluate_4688,
}

# Order matters: specific rules first, the general sudo rule last.
LINUX_EVALUATORS: List[Evaluator] = [
    evaluate_ssh_bruteforce, evaluate_ssh_success_after_failures,
    evaluate_root_ssh_login, evaluate_ssh_key_auth,
    evaluate_user_account_changed, evaluate_cron_or_systemd_persistence,
    evaluate_sshd_config_modified, evaluate_ssh_authorized_keys_modified,
    evaluate_suspicious_command_execution, evaluate_sudo_privilege_escalation,
]


def _run(evaluator: Evaluator, engine, event: Event) -> Optional[Alert]:
    try:
        return evaluator(engine, event)
    except Exception:  # noqa: BLE001 - isolate one broken rule from the rest
        log.exception("rule %s crashed on event %s", getattr(evaluator, "__name__", evaluator),
                      getattr(event, "eventId", "?"))
        return None


def evaluate_event(engine, event: Event) -> Optional[Alert]:
    """Route one normalized event to its rule(s). Returns the alert if one fires."""
    with engine._lock:  # collectors and the HTTP server may share one engine
        return _evaluate_locked(engine, event)


def _evaluate_locked(engine, event: Event) -> Optional[Alert]:
    engine.begin_event(event)

    if getattr(event, "osFamily", "windows") == "linux":
        for evaluator in LINUX_EVALUATORS:
            alert = _run(evaluator, engine, event)
            if alert:
                return alert
        return None

    event_id = int(event.eventId) if str(event.eventId).isdigit() else 0
    evaluator = WINDOWS_EVALUATORS.get(event_id)
    if evaluator is None:
        return None
    return _run(evaluator, engine, event)
