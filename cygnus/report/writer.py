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
    sev_icon = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢","Informational":"🔵"}.get(finding.severity,"•")
    conf_icon = {"High":"✅","Medium":"⚠️","Low":"🔍"}.get(finding.confidence,"•")
    return (
        f"### {sev_icon} Finding {index}: {finding.name}\n"
        f"- **Asset**: {finding.asset_type.value}  |  **Severity**: {finding.severity}  |  **Confidence**: {conf_icon} {finding.confidence}  |  **Status**: {finding.status}\n"
        f"- **Observed At**: {finding.observed_at}\n- **Component**: `{finding.component}`\n- **Evidence**: {evidence}{cve}\n"
        f"- **Root Cause**: {finding.root_cause}\n- **Exploitation Vector**: {finding.exploitation_vector}\n"
        f"- **Remediation**: {finding.remediation}\n"
    )


def to_markdown(report: ScanReport) -> str:
    ran = sum(result.status == "ran" for result in report.module_results)
    skipped = sum(result.status == "skipped" for result in report.module_results)
    errors = sum(result.status == "error" for result in report.module_results)
    profile = ", ".join(f"{item.type.value} ({item.confidence})" for item in report.profile.classifications)
    counts = Counter(item.severity for item in report.confirmed)
    total = ", ".join(f"{'🔴' if name=='Critical' else '🟠' if name=='High' else '🟡' if name=='Medium' else '🟢'}{name}: {counts.get(name, 0)}" for name in ("Critical", "High", "Medium", "Low", "Informational"))
    # catalog cross-reference
    try:
        from cygnus.modules.vulnerability_catalog import VULNERABILITY_CATALOG
        catalog_total = len(VULNERABILITY_CATALOG)
        catalog_ref = f"{catalog_total}-family CYGNUS catalog"
    except Exception:
        catalog_ref = "vulnerability catalog"
    lines = [
        "# 🛡️ CYGNUS Evidence-Based Security Report",
        "",
        "### 🛠️ SCAN STATUS",
        "",
        f"- **Mode**: {report.mode.value}",
        f"- **Target**: `{report.profile.target}`",
        f"- **Detected asset types**: {profile}",
        f"- **Authorization**: {report.authorization_reference}",
        f"- **Modules**: {ran} ran / {skipped} skipped / {errors} errors / {len(report.module_results)} discovered",
        f"- **Evidence validation**: {len(report.discarded_findings)} finding(s) discarded (fail-closed)",
        f"- **Catalog reference**: {catalog_ref} — findings map to catalog families with captured evidence",
        "",
        "### 🚨 CONFIRMED FINDINGS (evidence-backed only)",
        "",
        f"**Severity totals** — {total}",
        "",
    ]
    if report.confirmed:
        lines.extend(_finding(i, finding) for i, finding in enumerate(report.confirmed, 1))
    else:
        lines.append("_No confirmed findings — excellent! Continue continuous verification._\n")
    lines.extend(["", "### 🟡 NEEDS MANUAL VERIFICATION", "", "_Excluded from confirmed severity totals — weak evidence or public-interface indicators._", ""])
    if report.manual:
        lines.extend(_finding(i, finding) for i, finding in enumerate(report.manual, 1))
    else:
        lines.append("_None._\n")
    lines.extend(["", "### 🔗 EXPLOIT CHAINS (rule-based, confirmed findings only)", ""])
    if report.chains:
        lines.extend(f"- **{chain['name']}** — {' + '.join(chain['finding_ids'])}: {chain['impact']}" for chain in report.chains)
    else:
        lines.append("_No chain rule was satisfied by confirmed findings._")
    lines.extend(["", "### 🧠 NEXT STEPS & REMEDIATION PRIORITIES", ""])
    lines.extend(f"- {step}" for step in report.next_steps)
    lines.extend(["", "---", "", "### 📊 Module execution ledger", ""])
    # sort ran first
    ordered = sorted(report.module_results, key=lambda r: {"ran":0,"skipped":1,"error":2}.get(r.status,3))
    for result in ordered:
        icon = {"ran":"✅","skipped":"⏭️","error":"❌"}.get(result.status,"•")
        lines.append(f"- {icon} `{result.module}` — **{result.status}**: {result.reason}")
    if report.discarded_findings:
        lines.extend(["", "#### Discarded candidates (fail-closed audit)", ""])
        lines.extend(f"- {d}" for d in report.discarded_findings[:10])
        if len(report.discarded_findings) > 10:
            lines.append(f"- … and {len(report.discarded_findings)-10} more")
    lines.extend(["", "---", "", f"_CYGNUS • Evidence-Based • Verification-Driven • Catalog: 98 families • Report generated live_"])
    return "\n".join(lines) + "\n"
