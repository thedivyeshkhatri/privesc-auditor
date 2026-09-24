"""
Parses system-wide cron locations and flags any scheduled job whose
target script is writable by the current user - this is one of the
highest-confidence privesc paths, since it typically means:
"a script run automatically as root can be edited by me."
"""

import os
import shlex

from core.finding import Finding, Severity

NAME = "Cron"

CRON_LOCATIONS = ["/etc/crontab"]


def _extract_script_paths(cron_line: str) -> list[str]:
    """
    Small heuristic parser for system crontab lines, which look like:
        '* * * * * root /opt/backup.sh --flag > /dev/null 2>&1'
    (5 schedule fields, then a user field, then the command).

    We only want the *executed command*, not every absolute path on the
    line - otherwise redirect targets like /dev/null or arguments that
    happen to be file paths get misidentified as "the script that runs".
    """
    try:
        tokens = shlex.split(cron_line)
    except ValueError:
        tokens = cron_line.split()

    # Need at minimum: 5 schedule fields + user + command = 7 tokens
    if len(tokens) < 7:
        return []

    # Skip 5 schedule fields + 1 user field; the next token is the command
    command_token = tokens[6]

    # Stop at the first shell redirect/pipe/operator if shlex missed it
    if command_token in (">", ">>", "<", "|", "&", ";"):
        return []

    if command_token.startswith("/") and os.path.exists(command_token):
        return [command_token]
    return []


def _read_cron_file(filepath: str) -> list[str]:
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError):
        return []

    script_paths = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        script_paths.extend(_extract_script_paths(line))
    return script_paths


def _gather_all_cron_scripts() -> set[str]:
    all_paths = set()

    for filepath in CRON_LOCATIONS:
        all_paths.update(_read_cron_file(filepath))

    # /etc/cron.d/* files use crontab syntax (schedule + user + command)
    if os.path.isdir("/etc/cron.d"):
        for entry in os.listdir("/etc/cron.d"):
            full_path = os.path.join("/etc/cron.d", entry)
            if os.path.isfile(full_path):
                all_paths.update(_read_cron_file(full_path))

    # cron.daily/hourly/weekly/monthly directories contain the scripts
    # themselves (run-parts executes every file in the directory directly)
    for cron_dir in ["/etc/cron.daily", "/etc/cron.hourly",
                      "/etc/cron.weekly", "/etc/cron.monthly"]:
        if not os.path.isdir(cron_dir):
            continue
        for entry in os.listdir(cron_dir):
            full_path = os.path.join(cron_dir, entry)
            if os.path.isfile(full_path):
                all_paths.add(full_path)

    return all_paths


def run() -> list[Finding]:
    findings = []
    script_paths = _gather_all_cron_scripts()

    for idx, path in enumerate(sorted(script_paths), start=1):
        try:
            writable = os.access(path, os.W_OK)
            mode = oct(os.stat(path).st_mode)
        except OSError:
            continue

        if writable:
            findings.append(
                Finding(
                    id=f"CRON-{idx:03d}",
                    title=f"Cron-executed script is writable by current user: {path}",
                    severity=Severity.CRITICAL,
                    category=NAME,
                    evidence=f"Path: {path}\nPermissions: {mode}",
                    impact=(
                        "This script is referenced by a scheduled cron job. "
                        "If the job runs as root (or another privileged "
                        "user), a local user able to modify this file can "
                        "insert arbitrary commands that will later execute "
                        "with that privilege level, e.g. on the next "
                        "scheduled run."
                    ),
                    remediation=(
                        f"Restrict write access: chown root:root {path} && "
                        f"chmod 700 {path}. Ensure the containing directory "
                        f"is not writable by unprivileged users either."
                    ),
                    affected_path=path,
                )
            )
    return findings
