"""
Shared Finding data structure.

Every check module returns a list of Finding objects using this schema,
so the runner/reporter don't need to know anything about individual checks.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Higher number = more severe. Used for sorting."""
        return {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }[self]


@dataclass
class Finding:
    id: str                     # e.g. "SUID-001"
    title: str                  # short human-readable summary
    severity: Severity
    category: str                # "SUID", "Cron", "Sudo", "Writable Path", etc.
    evidence: str                # raw command output / permission bits / file paths
    impact: str                  # plain-English explanation of what an attacker could do
    remediation: str             # how to fix it
    affected_path: str = ""      # file / service / user this relates to
    references: list[str] = field(default_factory=list)  # e.g. GTFOBins links

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d
