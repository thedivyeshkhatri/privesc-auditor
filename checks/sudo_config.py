"""
Runs `sudo -l` for the current user and flags dangerous configurations:
  - NOPASSWD entries
  - Wildcard permissions
  - Unrestricted "ALL" access
  - Binaries known to allow a sudo bypass to a root shell (GTFOBins "sudo" list)

IMPORTANT: `sudo -l` output contains several *kinds* of lines - section
headers, "Defaults" lines (global sudo settings, not permission grants),
and the actual permission entries themselves. Only the permission entries
tell you what a user is allowed to *run*. Everything else is noise that
can accidentally contain words that look like binary names (e.g. the
header "Command-specific defaults" contains the substring "man", and
"visudo" contains "vi") - naive substring matching against the whole
output produces false positives from these headers. This parser only
evaluates real permission lines, and matches binaries as whole path
basenames rather than arbitrary substrings.
"""

import os
import subprocess

from core.finding import Finding, Severity

NAME = "Sudo"

# Subset of GTFOBins entries known to grant a root shell when run via sudo
SUDO_BYPASS_BINARIES = {
    "vim", "vi", "less", "more", "man", "awk", "find", "nmap", "python",
    "python3", "perl", "ruby", "env", "bash", "sh", "gdb", "docker",
    "ftp", "nano",
}

# Marker for the section of `sudo -l` output that actually lists what
# the user may run. Only lines inside this section are permission grants.
COMMANDS_SECTION_START = "may run the following commands"

# Any of these markers start a *different* section (Defaults, etc.) -
# seeing one means we've left the commands section.
OTHER_SECTION_MARKERS = (
    "matching defaults entries",
    "runas and command-specific defaults",
)


def _get_sudo_l_output() -> str | None:
    try:
        result = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # non-zero exit typically means sudo requires a password / no perms
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _extract_permission_lines(sudo_l_output: str) -> list[str]:
    """
    Return only the lines that are genuine permission grants, e.g.:
        (ALL : ALL) ALL
        (root) NOPASSWD: /usr/bin/vim
        (root) NOPASSWD: /usr/bin/find, /usr/bin/nmap
    Excludes header lines and "Defaults" entries entirely.
    """
    in_commands_section = False
    permission_lines = []

    for raw_line in sudo_l_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lowered = line.lower()

        if COMMANDS_SECTION_START in lowered:
            in_commands_section = True
            continue

        if any(marker in lowered for marker in OTHER_SECTION_MARKERS):
            in_commands_section = False
            continue

        # A genuine permission entry always starts with a runas spec
        # in parentheses, e.g. "(ALL : ALL)" or "(root)".
        if in_commands_section and line.startswith("("):
            permission_lines.append(line)

    return permission_lines


def _extract_commands(permission_line: str) -> str:
    """
    Strip the leading '(runas spec)' and any NOPASSWD:/PASSWD: tag,
    returning just the command portion, e.g.:
        "(root) NOPASSWD: /usr/bin/vim" -> "/usr/bin/vim"
        "(ALL : ALL) ALL"               -> "ALL"
    """
    if ")" in permission_line:
        remainder = permission_line.split(")", 1)[1].strip()
    else:
        remainder = permission_line

    for tag in ("NOPASSWD:", "PASSWD:"):
        if remainder.startswith(tag):
            remainder = remainder[len(tag):].strip()

    return remainder


def _matches_known_bypass_binary(command_text: str) -> set[str]:
    """
    Given the command portion of a permission line, return the set of
    known-bypass binaries actually referenced - matched as whole path
    basenames, not arbitrary substrings.
    """
    matches = set()
    for command in command_text.split(","):
        command = command.strip()
        if not command:
            continue
        first_token = command.split()[0] if command.split() else command
        basename = os.path.basename(first_token)
        if basename in SUDO_BYPASS_BINARIES:
            matches.add(basename)
    return matches


def run() -> list[Finding]:
    findings = []
    output = _get_sudo_l_output()

    if not output:
        return findings

    permission_lines = _extract_permission_lines(output)
    counter = 1

    for line in permission_lines:
        command_text = _extract_commands(line)

        if "NOPASSWD" in line:
            findings.append(
                Finding(
                    id=f"SUDO-{counter:03d}",
                    title="NOPASSWD sudo entry found",
                    severity=Severity.HIGH,
                    category=NAME,
                    evidence=line,
                    impact=(
                        "This entry allows running the listed command as "
                        "root without a password. If the command itself "
                        "can be abused to spawn a shell or write files "
                        "(see GTFOBins), this is a direct path to a root "
                        "shell."
                    ),
                    remediation=(
                        "Remove NOPASSWD unless strictly required, and "
                        "restrict the command to a minimal, non-abusable "
                        "binary with fixed arguments."
                    ),
                    affected_path="/etc/sudoers (or /etc/sudoers.d/*)",
                )
            )
            counter += 1

        # Wildcard in the *command* portion only, not the whole line
        # (e.g. "/usr/bin/*" is a wildcard; "ALL" is a distinct keyword).
        if "*" in command_text:
            findings.append(
                Finding(
                    id=f"SUDO-{counter:03d}",
                    title="Wildcard sudo permission found",
                    severity=Severity.MEDIUM,
                    category=NAME,
                    evidence=line,
                    impact=(
                        "A wildcard in the allowed command/arguments can "
                        "often be abused to pass unexpected arguments and "
                        "escalate privileges beyond what was intended."
                    ),
                    remediation=(
                        "Replace wildcards with an explicit, minimal list "
                        "of allowed arguments."
                    ),
                    affected_path="/etc/sudoers (or /etc/sudoers.d/*)",
                )
            )
            counter += 1

        for binary in _matches_known_bypass_binary(command_text):
            findings.append(
                Finding(
                    id=f"SUDO-{counter:03d}",
                    title=f"Sudo-permitted binary with known bypass: {binary}",
                    severity=Severity.CRITICAL,
                    category=NAME,
                    evidence=line,
                    impact=(
                        f"'{binary}' is documented on GTFOBins as "
                        f"capable of spawning a shell or performing "
                        f"file read/write when invoked via sudo, which "
                        f"typically results in a full root shell."
                    ),
                    remediation=(
                        f"Remove sudo access to '{binary}', or restrict "
                        f"it with fixed, non-exploitable arguments."
                    ),
                    affected_path="/etc/sudoers (or /etc/sudoers.d/*)",
                    references=[f"https://gtfobins.github.io/gtfobins/{binary}/#sudo"],
                )
            )
            counter += 1

        # "ALL" with no restriction at all - the user can run anything.
        if command_text.strip() == "ALL":
            findings.append(
                Finding(
                    id=f"SUDO-{counter:03d}",
                    title="Unrestricted sudo access (ALL commands permitted)",
                    severity=Severity.CRITICAL if "NOPASSWD" in line else Severity.HIGH,
                    category=NAME,
                    evidence=line,
                    impact=(
                        "This entry permits running any command as the "
                        "specified target user(s), which for (ALL) or "
                        "(root) means full root access with no "
                        "restriction on which commands are allowed."
                    ),
                    remediation=(
                        "Restrict sudo access to only the specific "
                        "commands actually required, rather than "
                        "unrestricted ALL."
                    ),
                    affected_path="/etc/sudoers (or /etc/sudoers.d/*)",
                )
            )
            counter += 1

    return findings
