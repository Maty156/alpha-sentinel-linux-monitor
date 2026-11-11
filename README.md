# Alpha Sentinel - Python port (v0.2.0)

AD / Linux attack monitor with a web dashboard. It reads Windows event exports (replay) and Linux
auth logs / the systemd journal, detects attacks, and shows them in a login-protected dashboard.

* **Windows rules (36)** - ported from `AlphaSentinel.ps1` and checked against its real output on 43 fixtures
  (`python tools/verify_all.py`). Use them via `replay` on `wevtutil` XML exports.
* **Linux rules (10)** - SSH brute force / success-after-failures / root login / key login, account changes,
  cron + systemd persistence, `sshd_config` and `authorized_keys` edits, suspicious commands, sudo.
* **Dashboard** - overview, alerts (acknowledge, status, notes), events, hosts, rules. Assets, attack paths,
  chains, reports, user management and the audit preflight are not ported yet (they answer HTTP 501).

## Install and run

    python3 -m venv .venv && . .venv/bin/activate
    pip install -e .
    alpha-sentinel create-admin                 # first dashboard login (asks for a password, min 12 chars)
    sudo ./start-sentinel.sh server             # dashboard on http://127.0.0.1:8443 + log collection
    # or step by step:
    alpha-sentinel server --collect             # --host 0.0.0.0 only behind TLS / an SSH tunnel
    alpha-sentinel collector --once             # cron: process new log lines, write alerts.jsonl
    alpha-sentinel collector --server http://127.0.0.1:8443 --key "$ALPHA_SENTINEL_COLLECTOR_KEY"
    alpha-sentinel replay tests/fixtures/       # run exported Windows event XML

Reading `/var/log/auth.log` and the journal needs root or membership of the `adm` / `systemd-journal` groups.
Copy `config.example.yaml` to `/etc/alpha-sentinel/config.yaml` to change the log sources.

State (users, alert history `alerts.jsonl`, log offsets) lives in `/var/lib/alpha-sentinel`, or
`~/.local/state/alpha-sentinel` when that is not writable; override with `ALPHA_SENTINEL_STATE_DIR`.
Files holding credentials or alerts are created `0600`.

## Security notes
* Sign-in is rate limited per address; sessions are HttpOnly + SameSite=Strict cookies (8 h, 30 min idle).
* The server speaks plain HTTP and binds to localhost by default - do not expose it without TLS in front.
* Forwarding alerts to a dashboard needs `ALPHA_SENTINEL_COLLECTOR_KEY` set on both sides (compared in constant time).

## Development
    pip install -e ".[dev]"
    python tools/verify_all.py                  # pytest + strict oracle replay
See `PORT_STATUS.md` for coverage and `CHANGELOG.md` for what changed.
