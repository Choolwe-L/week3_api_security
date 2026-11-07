#!/usr/bin/env python3
"""
analyze_report.py — turn the ZAP JSON report into a prioritized findings list.

Reads the traditional-json report produced by run_zap_scan.sh and writes:
  - deliverables/03_ZAP_Findings_Prioritized.md  (risk-ordered table + detail)

Usage:
    python3 scripts/analyze_report.py zap/reports/zap_fitness_api_report.json
"""
import json
import sys
import html
from pathlib import Path

RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
CONFIDENCE = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}


def load_alerts(report_path: Path):
    data = json.loads(report_path.read_text())
    alerts = []
    for site in data.get("site", []):
        host = site.get("@name", "")
        for a in site.get("alerts", []):
            instances = a.get("instances", [])
            alerts.append(
                {
                    "name": a.get("alert") or a.get("name", ""),
                    "risk": (a.get("riskdesc", "").split(" ")[0] or "Informational"),
                    "confidence": CONFIDENCE.get(str(a.get("confidence", "")), a.get("confidence", "")),
                    "cwe": a.get("cweid", ""),
                    "wasc": a.get("wascid", ""),
                    "count": a.get("count", len(instances)),
                    "desc": a.get("desc", ""),
                    "solution": a.get("solution", ""),
                    "ref": a.get("reference", ""),
                    "host": host,
                    "instances": [i.get("uri", "") for i in instances][:8],
                }
            )
    alerts.sort(key=lambda x: (RISK_ORDER.get(x["risk"], 9), x["name"]))
    return alerts


def strip_html(s: str) -> str:
    import re

    return html.unescape(re.sub("<[^>]+>", "", s or "")).strip()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    report = Path(sys.argv[1])
    alerts = load_alerts(report)

    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for a in alerts:
        counts[a["risk"]] = counts.get(a["risk"], 0) + 1

    out = Path(__file__).resolve().parents[1] / "deliverables" / "03_ZAP_Findings_Prioritized.md"
    lines = []
    lines.append("# Week 3 — ZAP Automated Scan: Prioritized Findings\n")
    lines.append(
        "Generated from the OWASP ZAP traditional-json report "
        f"(`{report.name}`) by `scripts/analyze_report.py`.\n"
    )
    lines.append("## Risk summary\n")
    lines.append("| Risk | Distinct alerts |")
    lines.append("|------|-----------------|")
    for r in ["High", "Medium", "Low", "Informational"]:
        lines.append(f"| {r} | {counts.get(r, 0)} |")
    lines.append("")
    lines.append("## Findings (highest risk first)\n")
    lines.append("| # | Risk | Confidence | Alert | CWE | Instances |")
    lines.append("|---|------|-----------|-------|-----|-----------|")
    for i, a in enumerate(alerts, 1):
        lines.append(
            f"| {i} | {a['risk']} | {a['confidence']} | {a['name']} | "
            f"{a['cwe']} | {a['count']} |"
        )
    lines.append("")
    lines.append("## Detail\n")
    for i, a in enumerate(alerts, 1):
        lines.append(f"### {i}. {a['name']}  _({a['risk']} / {a['confidence']})_\n")
        lines.append(f"- **CWE:** {a['cwe']}  **WASC:** {a['wasc']}  **Instances:** {a['count']}")
        if a["instances"]:
            lines.append("- **Example URLs:**")
            for u in a["instances"]:
                lines.append(f"  - `{u}`")
        desc = strip_html(a["desc"])
        sol = strip_html(a["solution"])
        if desc:
            lines.append(f"- **Description:** {desc}")
        if sol:
            lines.append(f"- **Remediation:** {sol}")
        lines.append("")

    out.write_text("\n".join(lines))
    print(f"[+] Wrote {out}")
    print(f"    High={counts['High']} Medium={counts['Medium']} "
          f"Low={counts['Low']} Info={counts['Informational']}")


if __name__ == "__main__":
    main()
