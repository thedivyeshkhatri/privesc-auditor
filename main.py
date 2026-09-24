#!/usr/bin/env python3
"""
privesc-auditor - Local Linux Privilege Escalation Auditor

Scans the local machine for common privilege escalation vectors
(SUID binaries, writable cron scripts, sudo misconfigurations, writable
paths, Docker group membership, insecure env/config, and services running
as root with writable targets) and reports them with severity, evidence,
impact, and remediation. Does not exploit anything - report-only.

Usage:
    python3 main.py
    python3 main.py --output html --outfile report.html
    python3 main.py --output json --outfile findings.json
    python3 main.py --category sudo,cron
    python3 main.py --list-categories

For use only on systems you own or are explicitly authorized to assess.
"""

import argparse
import importlib
import sys

from core.reporter import print_console_report, write_html_report, write_json_report
from core.runner import discover_check_modules, run_all_checks


def list_categories():
    print("Available check categories:")
    for module_name in discover_check_modules():
        module = importlib.import_module(f"checks.{module_name}")
        category_name = getattr(module, "NAME", module_name)
        print(f"  - {category_name}  (module: {module_name})")


def main():
    parser = argparse.ArgumentParser(
        description="Local Linux privilege escalation auditor (report-only)."
    )
    parser.add_argument(
        "--output",
        choices=["console", "html", "json", "all"],
        default="console",
        help="Output format(s). Default: console.",
    )
    parser.add_argument(
        "--outfile",
        default=None,
        help="Output file path for html/json (default: report.html / findings.json).",
    )
    parser.add_argument(
        "--category",
        default=None,
        help="Comma-separated list of check module names to run "
             "(see --list-categories). Default: run all checks.",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List available check categories and exit.",
    )

    args = parser.parse_args()

    if args.list_categories:
        list_categories()
        sys.exit(0)

    only_categories = args.category.split(",") if args.category else None

    print("[*] Running privilege escalation checks...")
    findings = run_all_checks(only_categories=only_categories)
    print(f"[*] Done. {len(findings)} finding(s).")

    if args.output in ("console", "all"):
        print_console_report(findings)

    if args.output in ("json", "all"):
        outfile = args.outfile if args.output == "json" and args.outfile else "findings.json"
        write_json_report(findings, outfile)

    if args.output in ("html", "all"):
        outfile = args.outfile if args.output == "html" and args.outfile else "report.html"
        write_html_report(findings, outfile)


if __name__ == "__main__":
    main()
