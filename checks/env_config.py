"""
Checks for insecurely stored credentials/config:
  - credential-looking environment variables
  - world-readable SSH private keys
  - shell history files containing likely-sensitive strings
"""

import os
import re
import stat

from core.finding import Finding, Severity

NAME = "Env/Config"

CREDENTIAL_ENV_PATTERN = re.compile(r"(pass|passwd|secret|token|api[_-]?key)", re.IGNORECASE)
CREDENTIAL_HISTORY_PATTERN = re.compile(r"(password|passwd|-p\s+\S+|secret|api[_-]?key)", re.IGNORECASE)

HISTORY_FILES = [
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.zsh_history"),
]

SSH_KEY_DIR = os.path.expanduser("~/.ssh")


def _check_env_vars() -> list[Finding]:
    findings = []
    counter = 1
    for key, value in os.environ.items():
        if CREDENTIAL_ENV_PATTERN.search(key):
            findings.append(
                Finding(
                    id=f"ENV-{counter:03d}",
                    title=f"Credential-like environment variable found: {key}",
                    severity=Severity.MEDIUM,
                    category=NAME,
                    evidence=f"{key}=<redacted, length {len(value)}>",
                    impact=(
                        "Environment variables are visible to any process "
                        "run by the same user (and sometimes readable via "
                        "/proc/<pid>/environ by other users depending on "
                        "system hardening). Storing secrets here increases "
                        "exposure risk."
                    ),
                    remediation=(
                        "Use a secrets manager or a restricted-permission "
                        "file instead of environment variables for "
                        "long-lived credentials."
                    ),
                    affected_path=f"env:{key}",
                )
            )
            counter += 1
    return findings


def _check_ssh_keys() -> list[Finding]:
    findings = []
    counter = 1
    if not os.path.isdir(SSH_KEY_DIR):
        return findings

    for entry in os.listdir(SSH_KEY_DIR):
        full_path = os.path.join(SSH_KEY_DIR, entry)
        if not os.path.isfile(full_path) or entry.endswith(".pub"):
            continue
        try:
            mode = os.stat(full_path).st_mode
        except OSError:
            continue

        # private keys should be 600 (owner read/write only)
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            findings.append(
                Finding(
                    id=f"SSHKEY-{counter:03d}",
                    title=f"SSH private key readable by group/others: {full_path}",
                    severity=Severity.HIGH,
                    category=NAME,
                    evidence=f"Path: {full_path}\nPermissions: {oct(mode)}",
                    impact=(
                        "A readable private key can be copied by another "
                        "local user and used to authenticate as this user "
                        "on any host that trusts the corresponding public "
                        "key."
                    ),
                    remediation=f"chmod 600 {full_path}",
                    affected_path=full_path,
                )
            )
            counter += 1
    return findings


def _check_shell_history() -> list[Finding]:
    findings = []
    counter = 1
    for history_file in HISTORY_FILES:
        if not os.path.isfile(history_file):
            continue
        try:
            with open(history_file, "r", errors="ignore") as f:
                lines = f.readlines()
        except (PermissionError, OSError):
            continue

        # Never copy matching commands into a report: shell history often
        # contains the very secret this check is looking for.
        matching_line_numbers = [
            str(number)
            for number, line in enumerate(lines, start=1)
            if CREDENTIAL_HISTORY_PATTERN.search(line)
        ]
        if matching_line_numbers:
            findings.append(
                Finding(
                    id=f"HIST-{counter:03d}",
                    title=f"Possible credentials in shell history: {history_file}",
                    severity=Severity.MEDIUM,
                    category=NAME,
                    evidence=(
                        f"{len(matching_line_numbers)} possible credential line(s) found. "
                        "Command contents are omitted to avoid exposing secrets.\n"
                        f"Line number(s): {', '.join(matching_line_numbers[:20])}"
                    ),
                    impact=(
                        "Commands containing credentials (e.g. mysql -p "
                        "or curl with an API key in the URL) persist in "
                        "shell history and can be read by anyone with "
                        "access to this history file."
                    ),
                    remediation=(
                        "Avoid passing secrets on the command line; use "
                        "environment files with restricted permissions or "
                        "interactive prompts instead. Clear the affected "
                        "history entries."
                    ),
                    affected_path=history_file,
                )
            )
            counter += 1
    return findings


def run() -> list[Finding]:
    return _check_env_vars() + _check_ssh_keys() + _check_shell_history()
