from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from cygnus import __version__
from cygnus.cli.banner import BANNER
from cygnus.core.audit import log_attempt
from cygnus.core.engine import ScanEngine
from cygnus.core.models import AssetType, ScanContext
from cygnus.core.plugin import discover_modules
from cygnus.core.scope import AuthorizationError, Scope, require_authorization
from cygnus.fingerprint.engine import Fingerprinter
from cygnus.report.writer import to_json, to_markdown


def parser() -> argparse.ArgumentParser:
    command=argparse.ArgumentParser(prog="cygnus",description="Authorized evidence-based passive security verifier")
    command.add_argument("target",nargs="?",help="target URL, host, IP, or local path")
    command.add_argument("-t","--target",dest="target_option",help="target (alternative to the positional argument)")
    command.add_argument("--scope",help="allowlist file containing domains, IP/CIDR, or local paths")
    command.add_argument("--authorization-ref",help="ticket/program/permission reference")
    command.add_argument("--authorized",action="store_true",help="confirm authorization for this specific target")
    command.add_argument("--active",action="store_true",help="enable separately gated active modules")
    command.add_argument("--active-authorized",action="store_true",help="second confirmation for active operations")
    command.add_argument("--active-authorization-ref")
    command.add_argument("--audit-log",default=".cygnus/audit.jsonl")
    command.add_argument("--timeout",type=float,default=3.0)
    command.add_argument("--repository-path",help="operator-provided local repository for static secret patterns")
    command.add_argument("--format",choices=("markdown","json"),default="markdown",help="output format for reports and catalog listings")
    command.add_argument("--output","-o",help="write report to file instead of stdout")
    command.add_argument("--recon","--profile-only",action="store_true",dest="profile_only",help="fingerprint only; do not run vulnerability modules")
    command.add_argument("--list-assets",action="store_true",help="list recognized asset types and exit")
    command.add_argument("--list-modules",action="store_true",help="list discovered check plugins and exit")
    command.add_argument("--list-vulnerabilities",action="store_true",help="list vulnerability catalog entries and exit")
    command.add_argument("--vuln-status",choices=("implemented","manual","catalog-only","all"),default="all",help="filter vulnerability catalog by implementation status")
    command.add_argument("--severity",choices=("Informational","Low","Medium","High","Critical"),help="minimum severity threshold for findings and catalog listing")
    command.add_argument("--vuln-search",metavar="TERM",help="search vulnerability catalog by name, tag, CWE, or OWASP")
    command.add_argument("--init-scope",metavar="FILE",help="create an allowlist containing the supplied target, then exit")
    command.add_argument("--version",action="version",version=f"CYGNUS {__version__}")
    return command


def _resolve_target(args, command: argparse.ArgumentParser) -> None:
    if args.target and args.target_option and args.target != args.target_option:
        command.error("provide the target either positionally or with -t/--target, not both")
    args.target=args.target_option or args.target
    if not args.target:command.error("a target is required (positional TARGET or -t/--target)")
    if not args.scope and not args.init_scope:command.error("--scope is required for scans")


def _utility(args) -> bool:
    if args.list_assets:
        print("CYGNUS Asset Taxonomy\n" + "="*60)
        print(f"{'Enum Name':<24} {'Display Name':<30} {'Category'}")
        print("-"*70)
        for item in AssetType:
            category = "Network" if "Server" in item.value or "Service" in item.value else \
                       "Web" if "Web" in item.value or "API" in item.value else \
                       "Cloud" if "Cloud" in item.value or "Kubernetes" in item.value or "Docker" in item.value else "General"
            print(f"{item.name:<24} {item.value:<30} {category}")
        print(f"\nTotal: {len(list(AssetType))} asset types recognized")
        return True
    if args.list_modules:
        modules = discover_modules()
        print(f"CYGNUS Discovered Check Modules ({len(modules)})\n" + "="*70)
        print(f"{'Module':<40} {'Asset Types':<25} {'Active?'}")
        print("-"*80)
        for module in modules:
            assets=", ".join(sorted(item.value for item in module.applies_to))[:60]
            active = "YES" if getattr(module, "requires_active", False) else "no"
            print(f"{module.name:<40} {assets:<60} {active}")
        print(f"\nTip: use --list-vulnerabilities to see the full 98-family catalog")
        return True
    if args.list_vulnerabilities:
        from cygnus.modules.vulnerability_catalog import filter_by_severity, count_by_status, count_by_severity, get_catalog
        # Start with severity filter
        entries = filter_by_severity(args.severity)
        # Apply status filter
        if getattr(args, "vuln_status", "all") != "all":
            entries = [e for e in entries if e.status == args.vuln_status]
        # Apply search filter
        search_term = getattr(args, "vuln_search", None)
        if search_term:
            st = search_term.lower()
            def matches(e):
                return st in e.name.lower() or st in e.id.lower() or st in e.cwe.lower() or st in e.owasp.lower() or any(st in tag for tag in e.tags) or st in e.category.lower()
            entries = [e for e in entries if matches(e)]
        # JSON output mode
        if args.format == "json":
            import json as _json
            payload = [
                {
                    "id": e.id, "name": e.name, "severity": e.severity, "status": e.status,
                    "category": e.category, "cwe": e.cwe, "owasp": e.owasp,
                    "tags": list(e.tags), "description": e.description
                } for e in entries
            ]
            print(_json.dumps({"total_catalog": 98, "displayed": len(payload), "entries": payload}, indent=2))
            return True
        # Human-friendly grouped table
        from collections import defaultdict
        grouped = defaultdict(list)
        for e in entries:
            grouped[e.status].append(e)
        print("\n" + "═"*78)
        print("  CYGNUS VULNERABILITY CATALOG — Evidence-Based · 98 Families")
        print("═"*78)
        if args.severity:
            print(f"  Severity filter: ≥ {args.severity}")
        if getattr(args, "vuln_status", "all") != "all":
            print(f"  Status filter: {args.vuln_status}")
        if search_term:
            print(f"  Search: '{search_term}'")
        print()
        severity_order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Informational":4}
        status_labels = {
            "implemented": "✅ IMPLEMENTED  — automated evidence-backed checks",
            "manual": "🔍 MANUAL       — requires operator verification",
            "catalog-only": "📚 CATALOG-ONLY — taxonomy reference, no automation yet",
        }
        total_displayed = 0
        for status in ("implemented", "manual", "catalog-only"):
            items = sorted(grouped.get(status, []), key=lambda x: (severity_order.get(x.severity,5), x.id))
            if not items:
                continue
            total_displayed += len(items)
            print(f"\n{status_labels.get(status, status.upper())}  [{len(items)}]")
            print("─"*78)
            print(f"  {'ID':<16} {'Severity':<10} {'Name'}")
            print("  " + "─"*74)
            for v in items:
                sev_icon = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢","Informational":"🔵"}.get(v.severity,"•")
                print(f"  {v.id:<16} {sev_icon} {v.severity:<8} {v.name}")
                print(f"  {'':16}   {v.category} · {v.cwe} · {v.owasp}")
                print(f"  {'':16}   tags: {', '.join(v.tags)}")
        totals_s = count_by_severity()
        totals_st = count_by_status()
        print("\n" + "─"*78)
        print(f"Displayed: {total_displayed}/98  |  Severity mix: " + ", ".join(f"{k}:{v}" for k,v in sorted(totals_s.items(), key=lambda x: severity_order.get(x[0],9))))
        print(f"Status mix: " + ", ".join(f"{k}:{v}" for k,v in totals_st.items()))
        print(f"Catalog source: cygnus.modules.vulnerability_catalog · evidence required for all findings")
        print("═"*78 + "\n")
        return True
    if args.init_scope:
        target=args.target_option or args.target
        if not target:raise ValueError("--init-scope requires TARGET or -t/--target")
        local=Path(target)
        entry=str(local.expanduser().resolve()) if local.exists() else Scope.target_host(target)
        path=Path(args.init_scope)
        if path.exists():raise ValueError(f"refusing to overwrite existing scope file: {path}")
        path.write_text(f"# CYGNUS authorized scope\n{entry}\n",encoding="utf-8")
        print(f"Created {path} with scope entry: {entry}"); return True
    return False


def _interactive_authorization(args) -> None:
    if not args.authorized and sys.stdin.isatty():
        response=input(f"Authorization gate: do you have explicit permission for {args.target}? Type 'yes': ")
        args.authorized=response.strip().lower()=="yes"
    if args.authorized and not args.authorization_ref and sys.stdin.isatty():
        args.authorization_ref=input("Authorization/scope reference: ").strip()
    if args.active and not args.active_authorized and sys.stdin.isatty():
        response=input("Separate active-operation confirmation required. Type 'ACTIVE-AUTHORIZED': ")
        args.active_authorized=response.strip()=="ACTIVE-AUTHORIZED"


def _profile_output(profile,mode,fmt):
    payload={"mode":mode.value,"target":profile.target,"normalized_target":profile.normalized_target,
             "asset_types":[{"type":item.type.value,"confidence":item.confidence,
             "evidence":[{"kind":ev.kind,"summary":ev.summary,"captured":ev.captured} for ev in item.evidence]} for item in profile.classifications]}
    if fmt=="json":return json.dumps(payload,indent=2,sort_keys=True)+"\n"
    lines=["### CYGNUS ASSET PROFILE",f"- Mode: {mode.value}",f"- Target: {profile.target}"]
    for item in profile.classifications:
        lines.append(f"- {item.type.value} — {item.confidence}: "+"; ".join(ev.summary for ev in item.evidence))
    return "\n".join(lines)+"\n"


async def execute(args) -> int:
    outcome="denied"
    try:
        reference=require_authorization(args.authorized,args.authorization_ref,args.active,args.active_authorized)
        scope=Scope.from_file(args.scope)
        if not scope.permits(args.target):raise AuthorizationError(f"target is outside allowlist scope: {args.target}")
        log_attempt(args.audit_log,args.target,reference,"authorized-in-scope")
        profile,mode=await Fingerprinter(args.timeout).run(args.target)
        print(f"\nOperating mode auto-detected from runtime access: {mode.value}\n",file=sys.stderr)
        if args.profile_only:rendered=_profile_output(profile,mode,args.format)
        else:
            context=ScanContext(mode,reference,args.active,args.active_authorization_ref,args.timeout,repository_path=args.repository_path, min_severity=args.severity)
            report=await ScanEngine().run(profile,context)
            rendered=to_json(report) if args.format=="json" else to_markdown(report)
        if args.output:
            Path(args.output).write_text(rendered,encoding="utf-8"); print(f"Report written to {args.output}",file=sys.stderr)
        else:print(rendered)
        outcome="completed"; return 0
    except (AuthorizationError,OSError,ValueError) as exc:
        print(f"CYGNUS blocked scan: {exc}",file=sys.stderr); return 2
    finally:
        if outcome!="completed":log_attempt(args.audit_log,args.target,args.authorization_ref,outcome)


def main() -> None:
    print(BANNER,flush=True)
    command=parser(); args=command.parse_args()
    try:
        if _utility(args):return
    except ValueError as exc:command.error(str(exc))
    _resolve_target(args,command); _interactive_authorization(args)
    raise SystemExit(asyncio.run(execute(args)))


if __name__=="__main__":main()
