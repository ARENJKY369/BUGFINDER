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
    command.add_argument("--format",choices=("markdown","json"),default="markdown")
    command.add_argument("--output","-o")
    command.add_argument("--recon","--profile-only",action="store_true",dest="profile_only",help="fingerprint only; do not run vulnerability modules")
    command.add_argument("--list-assets",action="store_true",help="list recognized asset types and exit")
    command.add_argument("--list-modules",action="store_true",help="list discovered check plugins and exit")
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
        print("\n".join(f"{item.name:<24} {item.value}" for item in AssetType)); return True
    if args.list_modules:
        for module in discover_modules():
            assets=", ".join(sorted(item.value for item in module.applies_to))
            print(f"{module.name:<38} {assets}")
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
            context=ScanContext(mode,reference,args.active,args.active_authorization_ref,args.timeout,repository_path=args.repository_path)
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
