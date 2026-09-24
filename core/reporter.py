"""
Renders findings as:
  - colored console output
  - JSON file
  - HTML report (via Jinja2)
"""

import json
import os
from datetime import datetime

from core.finding import Finding, Severity

# ANSI color codes - avoids requiring extra deps like `rich`/`colorama`
COLORS = {
    Severity.CRITICAL: "\033[1;41m",  # white on red
    Severity.HIGH: "\033[1;31m",      # red
    Severity.MEDIUM: "\033[1;33m",    # yellow
    Severity.LOW: "\033[0;37m",       # grey
}
RESET = "\033[0m"


def print_console_report(findings: list[Finding]) -> None:
    if not findings:
        print("\n[+] No findings. Either the system is well-configured, "
              "or checks were skipped due to permissions.\n")
        return

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    print("\n" + "=" * 70)
    print("  PRIVESC AUDITOR - SUMMARY")
    print("=" * 70)
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        color = COLORS[severity]
        print(f"  {color}{severity.value:<10}{RESET} : {counts[severity]}")
    print("=" * 70 + "\n")

    for f in findings:
        color = COLORS[f.severity]
        print(f"{color}[{f.severity.value}]{RESET} {f.id} - {f.title}")
        print(f"    Category   : {f.category}")
        print(f"    Path       : {f.affected_path}")
        print(f"    Impact     : {f.impact}")
        print(f"    Remediation: {f.remediation}")
        if f.references:
            print(f"    References : {', '.join(f.references)}")
        print(f"    Evidence   :\n      " + f.evidence.replace("\n", "\n      "))
        print("-" * 70)


def write_json_report(findings: list[Finding], outfile: str) -> None:
    data = {
        "generated_at": datetime.now().isoformat(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON report written to {outfile}")


def write_html_report(findings: list[Finding], outfile: str) -> None:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "htm", "xml"]),
    )
    template = env.get_template("report.html.j2")

    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    html = template.render(
        findings=findings,
        counts=counts,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(findings),
    )

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report written to {outfile}")
