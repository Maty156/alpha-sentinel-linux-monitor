# Tests

    pip install -e ".[test]"
    python tools/verify_all.py        # pytest + strict PowerShell-oracle replay

- `fixtures/*.xml` - real-shaped Windows events (shared with the PowerShell build).
- `oracle/ps_alerts.json` - what `AlphaSentinel.ps1 -ReplayPath` produces for each fixture. Refresh with
  `PWSH=/path/to/pwsh python tools/diff_replay.py --refresh-oracle` (needs `AlphaSentinel.ps1` next to `tools/`).
- `py/` - unit tests: rules vs oracle, engine/dedupe, Linux rules, collector, server (login, sessions,
  rate limit, CSRF, ingest), CLI.
