"""
Enumerates active systemd services and flags a writable unit file or
ExecStart target only when the service is configured to run as root.
"""

import os
import re
import subprocess

from core.finding import Finding, Severity

NAME = "Services"

EXEC_START_PATTERN = re.compile(r"^ExecStart=\s*(\S+)")
UNIT_DIRS = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]


def _list_service_units() -> list[str]:
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    units = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts:
            units.append(parts[0])
    return units


def _find_unit_file(unit_name: str) -> str | None:
    for unit_dir in UNIT_DIRS:
        candidate = os.path.join(unit_dir, unit_name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _service_runs_as_root(unit_name: str) -> bool:
    """An empty systemd User property means the service runs as root."""
    try:
        result = subprocess.run(
            ["systemctl", "show", unit_name, "--property=User", "--value", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

    if result.returncode != 0:
        return False
    configured_user = result.stdout.strip()
    return configured_user in ("", "root", "0")


def _extract_exec_start_binary(unit_file_path: str) -> str | None:
    try:
        with open(unit_file_path, "r") as f:
            for line in f:
                match = EXEC_START_PATTERN.match(line.strip())
                if match:
                    binary = match.group(1).lstrip("-")  # strip systemd '-' prefix
                    return binary.split()[0] if binary else None
    except (PermissionError, OSError):
        return None
    return None


def run() -> list[Finding]:
    findings = []
    counter = 1

    for unit_name in _list_service_units():
        if not _service_runs_as_root(unit_name):
            continue
        unit_file = _find_unit_file(unit_name)
        if not unit_file:
            continue

        # Writable unit file = attacker can change what the service runs
        if os.access(unit_file, os.W_OK):
            findings.append(
                Finding(
                    id=f"SVC-{counter:03d}",
                    title=f"Writable systemd unit file: {unit_file}",
                    severity=Severity.CRITICAL,
                    category=NAME,
                    evidence=f"Unit: {unit_name}\nFile: {unit_file}",
                    impact=(
                        "A writable unit file lets a local user redefine "
                        "what command this service executes. If the "
                        "service runs as root, restarting or the next "
                        "boot triggers execution of attacker-controlled "
                        "commands as root."
                    ),
                    remediation=(
                        f"Restrict permissions: chown root:root {unit_file} "
                        f"&& chmod 644 {unit_file}"
                    ),
                    affected_path=unit_file,
                )
            )
            counter += 1
            continue  # no need to also check the binary target

        exec_binary = _extract_exec_start_binary(unit_file)
        if exec_binary and os.path.isfile(exec_binary) and os.access(exec_binary, os.W_OK):
            findings.append(
                Finding(
                    id=f"SVC-{counter:03d}",
                    title=f"Service executes a writable binary/script: {exec_binary}",
                    severity=Severity.CRITICAL,
                    category=NAME,
                    evidence=f"Unit: {unit_name}\nExecStart target: {exec_binary}",
                    impact=(
                        "This service's ExecStart target can be modified "
                        "by the current user. If the service runs as "
                        "root, the next service (re)start will execute "
                        "attacker-controlled code as root."
                    ),
                    remediation=(
                        f"Restrict write access: chown root:root "
                        f"{exec_binary} && chmod 750 {exec_binary}"
                    ),
                    affected_path=exec_binary,
                )
            )
            counter += 1

    return findings
