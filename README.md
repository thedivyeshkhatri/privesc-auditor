# privesc-auditor

A local Linux privilege escalation auditor. Scans a machine for common
misconfigurations that could allow a local, unprivileged user to escalate
to root, and reports them with severity, evidence, plain-English impact,
and remediation steps. **It does not exploit anything — it only reports.**

## Why I built this

Tools like LinPEAS already do this well. I built my own version to make
sure I actually understand *why* each of these checks matters, rather
than running someone else's script and reading colored output I can't
fully explain. This project came out of noticing I kept manually
re-checking the same handful of things (SUID binaries, sudo -l, cron
permissions) on every TryHackMe box and CTF, and wanting to formalize
that process into something I built myself.

## What it checks

| Category      | What it looks for                                                   |
|----------------|----------------------------------------------------------------------|
| SUID           | SUID/SGID binaries, cross-referenced against known GTFOBins entries |
| Writable Path  | World/user-writable files in sensitive dirs, writable `$PATH` entries, `.` in `$PATH` |
| Cron           | Cron-executed scripts writable by the current user                  |
| Sudo           | `NOPASSWD` entries, wildcard permissions, GTFOBins sudo-bypass binaries |
| Docker         | Docker group membership, writable Docker socket                     |
| Env/Config     | Credential-like env vars, world-readable SSH private keys, secrets in shell history |
| Services       | Active root-run systemd services with writable unit files or `ExecStart` targets |

Each finding includes: ID, severity (LOW/MEDIUM/HIGH/CRITICAL), category,
evidence, impact, remediation, affected path, and references (e.g.
GTFOBins links) where relevant.

## Installation

```bash
git clone https://github.com/thedivyeshkhatri/privesc-auditor.git
cd privesc-auditor
python3 -m pip install -r requirements.txt
```

Requires Python 3.10 or newer.

No dependencies are required for console/JSON output — Jinja2 is only
needed for the HTML report.

## Usage

```bash
# Console output (default)
python3 main.py

# HTML report
python3 main.py --output html --outfile report.html

# Open the generated report in your desktop browser (Linux)
xdg-open report.html

# JSON output (for feeding into other tools, e.g. a chaining engine)
python3 main.py --output json --outfile findings.json

# Run only specific check categories
python3 main.py --category sudo,cron

# See available categories
python3 main.py --list-categories

# All output formats at once
python3 main.py --output all
```

## Example output

```
[CRITICAL] CRON-001 - Cron-executed script is writable by current user: /opt/backup.sh
    Category   : Cron
    Path       : /opt/backup.sh
    Impact     : This script is referenced by a scheduled cron job. If the
                  job runs as root, a local user able to modify this file
                  can insert arbitrary commands that will later execute
                  with that privilege level.
    Remediation: Restrict write access: chown root:root /opt/backup.sh && chmod 700 /opt/backup.sh
    Evidence   :
      Path: /opt/backup.sh
      Permissions: 0o100777
```

## Manual verification

I tested this against a deliberately misconfigured Ubuntu VM with:
- a cron job under `/etc/cron.d/` pointing to a world-writable script
- a `NOPASSWD` sudoers entry for `/usr/bin/vim`
- a SUID bit set on `/usr/bin/find`
- the current user added to the `docker` group

The tool flagged those four conditions in that lab run. Because the checks
are heuristic, results should be verified against the system configuration;
the scanner may miss issues or report false positives.

## Architecture

```
privesc-auditor/
├── main.py                  # CLI entrypoint
├── checks/                  # one file per check category
│   ├── suid_binaries.py
│   ├── writable_paths.py
│   ├── cron_jobs.py
│   ├── sudo_config.py
│   ├── docker_privileges.py
│   ├── env_config.py
│   └── services.py
├── core/
│   ├── finding.py            # shared Finding dataclass
│   ├── reporter.py           # console / JSON / HTML output
│   └── runner.py             # auto-discovers and runs check modules
├── templates/
│   └── report.html.j2
└── requirements.txt
```

Adding a new check is just a new file in `checks/` exposing a
`NAME: str` and a `run() -> list[Finding]` function — the runner picks
it up automatically, no other code needs to change.

## Scope and ethics

This tool is intended for use only on systems you own or are explicitly
authorized to assess (your own machines, lab VMs, or engagements with
written authorization). It performs read-only checks and does not modify
system state or attempt exploitation.

## Roadmap

- Add Windows checks for service permissions, unquoted paths, scheduled
  tasks, and AlwaysInstallElevated.
- Explore exporting findings to a companion tool that can model multi-step
  attack paths.
