"""
Finds SUID/SGID binaries on the filesystem and flags any that appear on a
known list of binaries commonly abusable for privilege escalation
(the same idea as GTFOBins - https://gtfobins.github.io/).

This does NOT attempt to exploit anything. It only reports.
"""

import os
import stat

from core.finding import Finding, Severity

NAME = "SUID"

# A curated subset of binaries known to be exploitable when SUID, based on GTFOBins.
KNOWN_EXPLOITABLE = {
    "nmap", "vim", "vi", "find", "python", "python3", "perl", "ruby",
    "less", "more", "man", "awk", "bash", "sh", "cp", "mv", "tar",
    "env", "nano", "ftp", "gdb", "strace", "docker", "node", "php",
}

SEARCH_ROOTS = ["/usr", "/bin", "/sbin", "/opt", "/usr/local"]


def _find_suid_sgid_files() -> list[str]:
    found = []
    for root_dir in SEARCH_ROOTS:
        for dirpath, dirnames, filenames in os.walk(root_dir, onerror=lambda e: None):
            # Skip proc-like or deeply irrelevant trees to keep this fast
            if "/proc" in dirpath:
                continue
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                try:
                    st = os.lstat(full_path)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                mode = st.st_mode
                if mode & stat.S_ISUID or mode & stat.S_ISGID:
                    found.append(full_path)
    return found


def run() -> list[Finding]:
    findings = []
    suid_files = _find_suid_sgid_files()

    for idx, path in enumerate(sorted(suid_files), start=1):
        binary_name = os.path.basename(path)
        is_known_dangerous = binary_name in KNOWN_EXPLOITABLE

        severity = Severity.HIGH if is_known_dangerous else Severity.LOW

        if is_known_dangerous:
            impact = (
                f"'{binary_name}' is known to be exploitable for privilege "
                f"escalation when SUID/SGID (see GTFOBins). If it runs as "
                f"root, a local user may be able to spawn a root shell or "
                f"read/write arbitrary files."
            )
            remediation = (
                f"Remove the SUID/SGID bit unless explicitly required: "
                f"chmod u-s,g-s {path}. Review why this binary needs "
                f"elevated privileges at all."
            )
        else:
            impact = (
                "This binary has the SUID/SGID bit set. It is not on the "
                "known-exploitable shortlist, but any SUID binary increases "
                "attack surface and should be reviewed."
            )
            remediation = (
                f"Confirm this binary genuinely needs SUID/SGID. If not, "
                f"remove it: chmod u-s,g-s {path}"
            )

        findings.append(
            Finding(
                id=f"SUID-{idx:03d}",
                title=f"SUID/SGID binary found: {path}",
                severity=severity,
                category=NAME,
                evidence=f"Path: {path}\nPermissions: {oct(os.lstat(path).st_mode)}",
                impact=impact,
                remediation=remediation,
                affected_path=path,
                references=(
                    [f"https://gtfobins.github.io/gtfobins/{binary_name}/"]
                    if is_known_dangerous
                    else []
                ),
            )
        )

    return findings
