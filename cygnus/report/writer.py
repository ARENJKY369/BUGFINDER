from __future__ import annotations

import json
from collections import Counter
from cygnus.core.models import Finding, ScanReport


def to_json(report: ScanReport) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)


def _finding(index: int, finding: Finding) -> str:
    evidence = " | ".join(f"{item.summary}: `{item.captured[:500].replace(chr(10), ' ')}`" for item in finding.evidence)
    cve = ""
    if finding.cve:
        cve = f" / CVE: {finding.cve['id']} ({finding.cve['source']}; cache updated {finding.cve['dataset_updated']})"
    return (
        f"Finding {index}: {finding.name} — {finding.asset_type.value} / {finding.severity} / {finding.confidence}\n"
        f"- Component: {finding.component}\n- Evidence: {evidence}{cve}\n"
        f"- Root Cause: {finding.root_cause}\n- Exploitation Vector: {finding.exploitation_vector}\n"
        f"- Remediation: {finding.remediation}\n"
    )


def to_markdown(report: ScanReport) -> str:
    ran = sum(result.status == "ran" for result in report.module_results)
    skipped = sum(result.status == "skipped" for result in report.module_results)
    errors = sum(result.status == "error" for result in report.module_results)
    profile = ", ".join(f"{item.type.value} ({item.confidence})" for item in report.profile.classifications)
    counts = Counter(item.severity for item in report.confirmed)
    total = ", ".join(f"{name}: {counts.get(name, 0)}" for name in ("Critical", "High", "Medium", "Low"))
    lines = [
        "### 🛠️ SCAN STATUS REPORT", "", f"- Mode: {report.mode.value}",
        f"- Target(s) + detected asset type(s) + confidence: {report.profile.target} — {profile}",
        f"- Authorization confirmed: Yes — {report.authorization_reference}",
        f"- Modules loaded vs skipped: {ran} ran / {skipped} skipped / {errors} errors / {len(report.module_results)} discovered", "",
        "### 🚨 CONFIRMED FINDINGS (evidence-backed only)", "", f"Confirmed severity totals — {total}", "",
    ]
    if report.confirmed:
        lines.extend(_finding(i, finding) for i, finding in enumerate(report.confirmed, 1))
    else:
        lines.append("No confirmed findings.\n")
    lines.extend(["### 🟡 NEEDS MANUAL VERIFICATION", "", "Excluded from confirmed severity totals.", ""])
    if report.manual:
        lines.extend(_finding(i, finding) for i, finding in enumerate(report.manual, 1))
    else:
        lines.append("None.\n")
    lines.extend(["### 🔗 EXPLOIT CHAINS (rule-based, confirmed findings only)", ""])
    if report.chains:
        lines.extend(f"- **{chain['name']}** — {' + '.join(chain['finding_ids'])}: {chain['impact']}" for chain in report.chains)
    else:
        lines.append("No chain rule was satisfied by confirmed findings.")
    lines.extend(["", "### 🧠 BOTTLENECK ANALYSIS & NEXT STEPS", ""])
    lines.extend(f"- {step}" for step in report.next_steps)
    lines.extend(["", "#### Module execution ledger", ""])
    lines.extend(f"- `{result.module}` — **{result.status}**: {result.reason}" for result in report.module_results)
    return "\n".join(lines) + "\n"
