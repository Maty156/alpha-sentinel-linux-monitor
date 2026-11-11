"""Log collectors for Alpha Sentinel - auditd, journal, syslog/auth.log.

Each source is read incrementally; offsets are persisted so a restart neither
re-alerts on old lines nor skips new ones. Alerts go to an `on_alert` callback
(the server passes one that shares its engine), and are always appended to the
alert history.
"""

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from alpha_sentinel import store
from alpha_sentinel.engine import Engine
from alpha_sentinel.normalize import normalize_event
from alpha_sentinel.rules import evaluate_event

log = logging.getLogger("alpha_sentinel.collector")

DEFAULT_SOURCES = [
    {"type": "syslog", "path": "/var/log/auth.log"},
    {"type": "journal", "units": ["sshd", "sudo"]},
]
UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,128}$")
STATE_FILE = "collector-state.json"
SAVE_EVERY_SECONDS = 5.0
POLL_SECONDS = 0.5


def load_config(path: Optional[str]) -> Dict[str, Any]:
    """Read the YAML config; a missing file means defaults, a broken one is an error."""
    cfg: Dict[str, Any] = {"log_sources": list(DEFAULT_SOURCES)}
    if not path or not os.path.exists(path):
        return cfg
    import yaml
    with open(path, encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    cfg.update(loaded)
    if not isinstance(cfg.get("log_sources"), list):
        raise ValueError(f"{path}: log_sources must be a list")
    return cfg


class LogCollector:
    def __init__(self, config: Dict[str, Any], engine: Optional[Engine] = None,
                 on_alert: Optional[Callable] = None):
        self.config = config
        self.engine = engine or Engine()
        self.on_alert = on_alert
        self.sources: List[Dict[str, Any]] = config.get("log_sources", DEFAULT_SOURCES)
        self.running = False
        self.state: Dict[str, Any] = store.load_json(STATE_FILE, {})
        self._last_save = time.monotonic()

    # ---- state ------------------------------------------------------------
    def save_state(self) -> None:
        try:
            store.save_json(STATE_FILE, self.state)
        except Exception:  # noqa: BLE001
            log.exception("could not save collector state")

    def _maybe_save(self) -> None:
        if time.monotonic() - self._last_save >= SAVE_EVERY_SECONDS:
            self.save_state()
            self._last_save = time.monotonic()

    # ---- processing -------------------------------------------------------
    def process_line(self, line: str, source: str) -> Optional[Any]:
        """Normalize one line and run it through the rules. Never raises."""
        line = line.strip()
        if not line:
            return None
        try:
            event = normalize_event(line, platform="linux")
            if event is None:
                return None
            if not event.timestamp:  # journal -o cat carries no time: stamp at read time
                event.timestamp = datetime.now(timezone.utc).isoformat()
            alert = evaluate_event(self.engine, event)
        except Exception:  # noqa: BLE001
            log.exception("failed to process %s line: %.120r", source, line)
            return None
        if alert:
            store.append_alert(alert)
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception:  # noqa: BLE001
                    log.exception("on_alert callback failed")
            else:
                print(f"[{source}] ALERT {alert.Severity}: {alert.RuleKey} - {alert.Description}")
        return alert

    # ---- file tailing -----------------------------------------------------
    def _read_new(self, path: str, kind: str, follow_start: bool) -> int:
        """Read lines added since the saved offset; returns lines processed.

        Detects rotation (inode changed or file shrank) and restarts at offset 0.
        On the very first run a followed file starts at its END (history is not
        replayed as fresh alerts); --once starts at the beginning.
        """
        key = f"{kind}:{path}"
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return 0
        saved = self.state.get(key)
        if saved is None:
            offset = st.st_size if follow_start else 0
        elif saved.get("inode") != st.st_ino or saved.get("offset", 0) > st.st_size:
            offset = 0  # rotated or truncated
        else:
            offset = saved["offset"]
        count = 0
        with open(path, "rb") as fh:
            fh.seek(offset)
            while True:
                raw = fh.readline()
                if not raw or not raw.endswith(b"\n"):
                    break  # partial last line: pick it up next poll
                offset = fh.tell()
                self.process_line(raw.decode("utf-8", errors="replace"), kind)
                count += 1
        self.state[key] = {"inode": st.st_ino, "offset": offset}
        return count

    async def tail_file(self, path: str, kind: str) -> None:
        if not os.path.exists(path):
            log.warning("%s log not found: %s (will keep checking)", kind, path)
        while self.running:
            try:
                self._read_new(path, kind, follow_start=True)
                self._maybe_save()
            except PermissionError:
                log.error("no permission to read %s (run as root or add the user to the adm group)", path)
                await asyncio.sleep(30)
            except Exception:  # noqa: BLE001
                log.exception("error reading %s", path)
            await asyncio.sleep(POLL_SECONDS)

    # ---- journal ----------------------------------------------------------
    def _journal_cmd(self, units: List[str], follow: bool) -> List[str]:
        bad = [u for u in units if not UNIT_RE.match(str(u))]
        if bad:
            raise ValueError(f"invalid journal unit name(s): {bad}")
        cursor = str(store.state_dir() / "journal.cursor")
        cmd = ["journalctl", "-o", "cat", "--no-pager", f"--cursor-file={cursor}"]
        if follow:
            cmd += ["-f", "-n", "0"]
        for u in units:
            cmd += ["-u", str(u)]
        return cmd

    async def tail_journal(self, units: List[str]) -> None:
        cmd = self._journal_cmd(units, follow=True)
        while self.running:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            except FileNotFoundError:
                log.error("journalctl not found; skipping journal source")
                return
            try:
                while self.running:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    self.process_line(line.decode("utf-8", errors="replace"), "journal")
                    self._maybe_save()
            finally:
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
            if self.running:
                await asyncio.sleep(5)  # journalctl exited: back off, then reconnect

    def journal_once(self, units: List[str]) -> int:
        import subprocess
        cmd = self._journal_cmd(units, follow=False)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False).stdout
        except FileNotFoundError:
            log.warning("journalctl not found; skipping journal source")
            return 0
        n = 0
        for line in out.splitlines():
            self.process_line(line, "journal")
            n += 1
        return n

    # ---- run --------------------------------------------------------------
    def run_once(self) -> int:
        """Process everything new in every source and return. For cron."""
        total = 0
        for src in self.sources:
            kind = src.get("type")
            if kind in ("syslog", "auditd"):
                total += self._read_new(src.get("path", "/var/log/auth.log"), kind, follow_start=False)
            elif kind == "journal":
                total += self.journal_once(src.get("units", ["sshd", "sudo"]))
            else:
                log.warning("unknown log source type: %r", kind)
        self.save_state()
        return total

    async def run(self) -> None:
        self.running = True
        tasks = []
        for src in self.sources:
            kind = src.get("type")
            if kind in ("syslog", "auditd"):
                tasks.append(asyncio.create_task(self.tail_file(src.get("path", "/var/log/auth.log"), kind)))
            elif kind == "journal":
                tasks.append(asyncio.create_task(self.tail_journal(src.get("units", ["sshd", "sudo"]))))
            else:
                log.warning("unknown log source type: %r", kind)
        try:
            await asyncio.gather(*tasks)
        finally:  # runs on Ctrl-C / cancellation too, so offsets are never lost
            self.running = False
            for t in tasks:
                t.cancel()
            self.save_state()

    def stop(self) -> None:
        self.running = False
        self.save_state()


def run_collector(config: str = "/etc/alpha-sentinel/config.yaml", once: bool = False,
                  server: Optional[str] = None, key: Optional[str] = None) -> None:
    """CLI entry point. With `server`+`key`, alerts are also forwarded to that dashboard."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(config)
    on_alert = None
    if server:
        from alpha_sentinel.outputs import make_forwarder
        on_alert = make_forwarder(server, key or os.environ.get("ALPHA_SENTINEL_COLLECTOR_KEY", ""))
    collector = LogCollector(cfg, on_alert=on_alert)
    if once:
        n = collector.run_once()
        print(f"processed {n} line(s), {len(collector.engine.alerts)} alert(s)")
        return
    print("Starting Alpha Sentinel collector (Ctrl-C to stop)...")
    try:
        asyncio.run(collector.run())
    except KeyboardInterrupt:
        print("\nCollector stopped")
