"""
Finds files/directories writable by the current user in sensitive
locations, and checks $PATH for hijackable (writable) entries.
"""

import os
import stat

from core.finding import Finding, Severity

NAME = "Writable Path"

SENSITIVE_DIRS = ["/etc", "/usr/local/bin", "/opt", "/etc/systemd/system"]


def _is_writable(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _check_sensitive_dirs() -> list[Finding]:
    findings = []
    counter = 1

    for base_dir in SENSITIVE_DIRS:
        if not os.path.isdir(base_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(base_dir, onerror=lambda e: None):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                if _is_writable(full_path) and not os.path.islink(full_path):
                    try:
                        mode = oct(os.stat(full_path).st_mode)
                    except OSError:
                        mode = "unknown"
                    findings.append(
                        Finding(
                            id=f"WRITE-{counter:03d}",
                            title=f"Writable file in sensitive directory: {full_path}",
                            severity=Severity.MEDIUM,
                            category=NAME,
                            evidence=f"Path: {full_path}\nPermissions: {mode}",
                            impact=(
                                "This file sits in a directory typically "
                                "trusted by privileged processes or the "
                                "system. If a privileged process reads, "
                                "executes, or sources this file, an "
                                "attacker who can write to it may gain "
                                "elevated privileges."
                            ),
                            remediation=(
                                f"Restrict write permissions: chmod o-w "
                                f"{full_path} (and verify group ownership "
                                f"is appropriate)."
                            ),
                            affected_path=full_path,
                        )
                    )
                    counter += 1
    return findings


def _check_path_hijack() -> list[Finding]:
    findings = []
    path_env = os.environ.get("PATH", "")
    entries = path_env.split(":")

    for idx, entry in enumerate(entries, start=1):
        if entry in ("", "."):
            findings.append(
                Finding(
                    id=f"PATHENV-{idx:03d}",
                    title="Current directory ('.') present in $PATH",
                    severity=Severity.HIGH,
                    category=NAME,
                    evidence=f"PATH={path_env}",
                    impact=(
                        "A relative/current-directory entry in $PATH means "
                        "running a common command name from an "
                        "attacker-controlled directory could execute a "
                        "malicious file instead of the intended system "
                        "binary."
                    ),
                    remediation="Remove '.' or empty entries from $PATH.",
                    affected_path="$PATH",
                )
            )
            continue

        if os.path.isdir(entry) and _is_writable(entry):
            findings.append(
                Finding(
                    id=f"PATHENV-{idx:03d}",
                    title=f"Writable directory in $PATH: {entry}",
                    severity=Severity.HIGH,
                    category=NAME,
                    evidence=f"PATH entry: {entry}",
                    impact=(
                        "Any user who can write to this directory can "
                        "place a malicious binary with the same name as a "
                        "common command. If a privileged process or "
                        "another user's shell has this directory earlier "
                        "in their $PATH, this can lead to code execution "
                        "under their privileges."
                    ),
                    remediation=(
                        f"Remove {entry} from $PATH, or restrict write "
                        f"access to trusted users only."
                    ),
                    affected_path=entry,
                )
            )
    return findings


def run() -> list[Finding]:
    return _check_sensitive_dirs() + _check_path_hijack()
