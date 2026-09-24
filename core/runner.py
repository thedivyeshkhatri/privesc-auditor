"""
Discovers every check module inside checks/ and runs it.

Each module in checks/ must expose:
    NAME: str                       -> short category name
    def run() -> list[Finding]      -> performs the check, returns findings

Adding a new check later is just: drop a new file in checks/ with a run()
function. Nothing else needs to change.
"""

import importlib
import pkgutil
import sys
import traceback

import checks
from core.finding import Finding


def discover_check_modules():
    """Yield every submodule inside the checks package."""
    for _, module_name, _ in pkgutil.iter_modules(checks.__path__):
        yield module_name


def run_all_checks(only_categories: list[str] | None = None) -> list[Finding]:
    """
    Run every check module and aggregate their findings.

    only_categories: if provided, only run modules whose NAME (lowercased)
    matches one of these (case-insensitive filter passed via --category).
    """
    all_findings: list[Finding] = []

    for module_name in discover_check_modules():
        module = importlib.import_module(f"checks.{module_name}")

        category_name = getattr(module, "NAME", module_name)

        if only_categories:
            if category_name.lower() not in [c.lower() for c in only_categories]:
                continue

        if not hasattr(module, "run"):
            continue

        try:
            findings = module.run()
            all_findings.extend(findings)
        except PermissionError as e:
            print(f"[!] {category_name}: skipped (permission denied) - {e}", file=sys.stderr)
        except Exception as e:
            print(f"[!] {category_name}: check failed with an error:", file=sys.stderr)
            traceback.print_exc()

    # Sort worst-first so the report reads top-down by severity
    all_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return all_findings
