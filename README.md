# ALPHA Sentinel for Linux - Python attack monitor (v0.2.0)

Linux / AD attack monitor with a web dashboard, built for the **Alpha Sentinel** graduation project.
This is the **Linux and Python edition**. The Windows PowerShell edition for Active Directory domain
controllers is in the sister repository: [Maty156/alpha-sentinel](https://github.com/Maty156/alpha-sentinel).

## The project: three repositories

Alpha Sentinel is built as three parts, each in its own repository:

| Repository | What it is |
|---|---|
| [alpha-sentinel-linux-monitor](https://github.com/Maty156/alpha-sentinel-linux-monitor) | **This repo.** Linux and Python edition of the monitor, with the dashboard and the Wolf AI assistant. |
| [alpha-sentinel](https://github.com/Maty156/alpha-sentinel) | Windows edition: one PowerShell script for Active Directory domain controllers, with its own dashboard and Wolf. |
| [alpha](https://github.com/Maty156/alpha) | The web portal that connects clients with admins: requests, messages, reports and certificates. |

They are separate on purpose: Windows and Linux have different logs, collectors and rules, so keeping them apart makes each one easier to test and debug.

## Project information

**Purpose.** Tools such as Wazuh are powerful but hard for students and small organisations to install
and learn. Alpha Sentinel is a simpler monitor: it reads the logs of a Linux server, detects common
attacks, explains them in plain language and suggests what to do - in one small Python package with a
login-protected web dashboard.

**Main features**
- **10 Linux detection rules** mapped to MITRE ATT&CK: SSH brute force, login success after repeated
  failures, direct root SSH login, SSH key login, user account changes, `authorized_keys` and
  `sshd_config` edits, cron / systemd persistence, sudo escalation, suspicious commands.
- **36 Windows rules** ported from the PowerShell edition, usable through `replay` on exported event XML.
- **Wolf, the AI assistant**: answers from the monitor's own data (alerts, coverage, rules). Works offline
  with built-in answers, or with a Gemini / OpenAI-compatible provider. The API key is stored on the
  server only and never sent to the browser. Chats are saved and have their own page.
- **Response playbook on every alert** with real Linux commands (block the IP with `ufw` / `iptables`,
  lock an account, review `auth.log`). Values from the logs are validated before they go into a command.
- **Dashboard behind a login**: overview, alerts with triage, events, hosts, rules, users and log sources
  in Settings, rule self-test and health checks.

**Video presentations** (each team member presents their own contribution):

| Team member | Video |
|---|---|
| Matyas Abreham (Team Lead) | [Watch](https://drive.google.com/file/d/1pql3-JQwtKaJQBLpZVIlGo1rbPO8A_a9/view?usp=sharing) |
| Surafel Ketema | [Watch](https://drive.google.com/file/d/18V6csm8dpqQxKfkVmqzdrMfwt_Z613_I/view?usp=sharing) |
| Omer Muzemil (Umer) | [Watch](https://drive.google.com/file/d/143rWGEcts4yoHhREwQLdP1QNYCLlSqBY/view?usp=drive_link) |

**Team**

| # | Full name | CTC ID | Role |
|---|---|---|---|
| 1 | Matyas Abreham | CTC-207-26 | Project Lead & Lead Developer (architecture, detection engine, dashboard, testing, documentation) |
| 2 | Nathnail Wassie | CTC-7656-26 | Frontend Developer |
| 3 | Abu Geleta | CTC-4372-26 | Backend Developer |
| 4 | Omer Muzemil | CTC-7061-26 | Backend Developer, Front Developer, Tester, Presenter |
| 5 | Surafel Ketema | CTC-378-26 | Frontend Developer |
| 6 | Eyorika Kassaye | CTC-6619-26 | Tester |

*Built with AI-assisted development (Hermes and Claude). The team lead directed the work, tested it on
a lab, and reviewed every change.*

---


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
