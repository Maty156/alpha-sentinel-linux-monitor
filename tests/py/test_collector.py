import os

import pytest

from alpha_sentinel import store
from alpha_sentinel.collectors import LogCollector, load_config

LINES = [f"Oct 29 10:00:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n" for i in range(1, 7)]


def make(tmp_path, content=""):
    log = tmp_path / "auth.log"
    log.write_text(content)
    cfg = {"log_sources": [{"type": "syslog", "path": str(log)}]}
    return log, cfg


def test_once_mode_actually_processes_logs(tmp_path):
    log, cfg = make(tmp_path, "".join(LINES))
    c = LogCollector(cfg)
    assert c.run_once() == 6
    assert [a.RuleKey for a in c.engine.alerts] == ["ssh_bruteforce"]
    assert len((store.state_dir() / "alerts.jsonl").read_text().splitlines()) == 1


def test_offsets_persist_so_restart_does_not_realert(tmp_path):
    log, cfg = make(tmp_path, "".join(LINES))
    LogCollector(cfg).run_once()
    again = LogCollector(cfg)
    assert again.run_once() == 0 and again.engine.alerts == []
    with open(log, "a") as fh:
        fh.write("Oct 29 10:01:00 web01 sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2\n")
    assert LogCollector(cfg).run_once() == 1


def test_log_rotation_is_detected(tmp_path):
    log, cfg = make(tmp_path, "".join(LINES))
    LogCollector(cfg).run_once()
    os.rename(log, tmp_path / "auth.log.1")
    log.write_text(LINES[0])                       # new, shorter file at the same path
    c = LogCollector(cfg)
    assert c.run_once() == 1


def test_partial_last_line_is_not_consumed(tmp_path):
    log, cfg = make(tmp_path, LINES[0] + "Oct 29 10:00:09 web01 sshd[1]: Failed pass")
    c = LogCollector(cfg)
    assert c.run_once() == 1
    with open(log, "a") as fh:
        fh.write("word for root from 203.0.113.5 port 22 ssh2\n")
    assert LogCollector(cfg).run_once() == 1


def test_journal_unit_names_are_validated_not_shell_interpolated(tmp_path):
    _, cfg = make(tmp_path)
    c = LogCollector(cfg)
    with pytest.raises(ValueError):
        c._journal_cmd(["sshd; rm -rf /"], follow=False)
    cmd = c._journal_cmd(["sshd", "sudo"], follow=True)
    assert isinstance(cmd, list) and cmd[0] == "journalctl" and "-u" in cmd


def test_unparseable_and_garbage_lines_never_raise(tmp_path):
    _, cfg = make(tmp_path)
    c = LogCollector(cfg)
    for junk in ("", "\x00\x01garbage", "COMMAND=", "Failed password"):
        c.process_line(junk, "syslog")


def test_config_errors_are_reported(tmp_path):
    bad = tmp_path / "c.yaml"
    bad.write_text("- just\n- a list\n")
    with pytest.raises(ValueError):
        load_config(str(bad))
    assert load_config(str(tmp_path / "missing.yaml"))["log_sources"]
