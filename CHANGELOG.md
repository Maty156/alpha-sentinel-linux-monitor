# Changelog (Python port)

## 0.2.1
- Wolf page in the sidebar with several chats and a New chat button (chats stay in the browser); the floating widget shares them.
- Wolf keeps the conversation across reloads (browser storage, Clear button) and remembers the last turns.
- Wolf: knows log-source health, collector state and per-rule results; built-in rule self-test (POST /api/selftest); full-screen chat toggle; missing auth.log no longer "blind" when journald works.
- AI settings: provider choice (Google AI Studio or any OpenAI-compatible service such as FreeLLMAPI), free-tier default gemini-3.1-flash-lite, type-or-pick model.
- Settings: Gemini API key now saves (server-side, 0600, or GEMINI_API_KEY env); Wolf uses Gemini when set and falls back to built-in answers. Sign-in name change works. Fixed PBKDF2 text.
- Linux build shows only the 10 Linux rules (set `ALPHA_SENTINEL_RULES=all|windows` to change); rules list sources (sshd, sudo...) instead of Windows event IDs.
- Wolf assistant works locally (`/api/bot/ask`), no external service.
- Settings > Users works (add, reset password, remove; asks for your password).
- Settings > Audit is now "Log sources": read-only check that auth.log/journal are readable and sshd logs enough.
- Attack Paths marked "Coming soon / example only"; Reports marked "Soon".
- Removed Windows/AD wording from the UI.

## 0.2.0

### Fixed - detection
- `import alpha_sentinel.rules` crashed (`NameError: Optional`), and `Engine.evaluate()` swallowed it, so **no rule ever fired** and the collector could not import. Errors in a rule are now logged with a traceback instead of hidden.
- Event fields read by the 4648 / 4657 / 4672 / 4697 / 4698 / 4728 / 5136 rules did not exist on the `Event` model (silent `AttributeError`). Added and mapped in the normalizer.
- Five rules were never ported (log_tampering 1102, audit_policy_changed 4719, firewall_rule_modified 4946-9, defender_disabled 5001/5010/5012, system_time_changed 4616) and `group_membership_removed` (4729/4733). All ported; 5141 now shares the 4662 DCSync/LDAP logic as in PowerShell.
- `gpo_or_admin_object_modified`: matched the object GUID instead of `ObjectClass`.
- Normalizer now picks `accountName` per event ID exactly like the PowerShell normalizer (4688 reported `SYSTEM`, 4104 an empty account, 4662/4698/... a guessed account).
- Dedupe now follows PowerShell: windows come from the rule catalog, repeats are folded into the open alert (Count, LastSeen, events) and **upgrade its severity in place**; an acknowledged/resolved alert no longer swallows new hits. All time logic uses event time, not the wall clock (replaying old logs no longer mis-dedupes). Timestamps with 7-9 fractional digits parse on every supported Python.
- Alerts now carry title, MITRE id/name, tactic and remediation from a catalog generated from `AlphaSentinel.ps1` (`rule_meta.py`) instead of `T0000 / Investigate immediately`.

### Fixed - Linux
- Linux events no longer run through Windows rules (`Event.osFamily`); `invalid user`, IPv6, ISO and classic syslog timestamps, and the real host name are parsed.
- `ssh_key_auth` could never fire; `ssh_success_after_failures` ignored time; sudo/suspicious-command dedupe never matched its own key; `user_account_changed` fired on `cat /etc/passwd`; `cron_or_systemd_persistence` fired on `systemctl status`; `ssh -c` matched `sh -c`.

### Fixed - collector
- `--once` did nothing; alerts were only printed and never reached the server. Alerts are persisted (`alerts.jsonl`), shared with the server in-process (`server --collect`) or forwarded (`collector --server URL --key K`).
- No shell: `journalctl` is run with an argument list and unit names are validated (was `create_subprocess_shell` with config text).
- Offsets save periodically and on Ctrl-C, handle log rotation/truncation and partial lines; a first run starts at the end of the file; config errors are reported.

### Fixed - server
- **Real authentication** (PBKDF2, constant-time, per-IP rate limit); previously *any* username/password logged in and every API route was open. HttpOnly + SameSite=Strict session cookie with absolute and idle timeouts; per-user sessions (was one global flag); same-origin check on POST; CSP and security headers. No token in `localStorage`.
- Binds to `127.0.0.1` by default. Overview, alerts (ack/status), events, hosts, rules and settings return real engine data. Unported endpoints return JSON 501, not HTML.
- `alpha-sentinel create-admin` creates the first account; the server refuses to start without one.

### Tooling
- `tools/diff_replay.py` compares as multisets and runs the Python side by default (its replay silently produced 0 alerts, which is why it always reported "30 mismatches"). Replay mode mirrors PowerShell `-ReplayPath`. The stored oracle was re-checked against a real PowerShell 7.4.6 run of the current script: 0 stale entries.
- ~100 pytest tests; `python tools/verify_all.py` runs everything.
- Removed the stale PowerShell changelog, `BLOCKERS.md`, `STAGE0_SUMMARY.md`, `VERIFY_REPORT.txt`, cache and egg-info.
