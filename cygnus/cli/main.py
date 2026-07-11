from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from cygnus.cli.banner import BANNER
from cygnus.core.audit import log_attempt
from cygnus.core.engine import ScanEngine
from cygnus.core.models import ScanContext
from cygnus.core.scope import AuthorizationError, Scope, require_authorization
from cygnus.fingerprint.engine import Fingerprinter
from cygnus.report.writer import to_json, to_markdown


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="cygnus", description="Authorized evidence-based passive security verifier")
    command.add_argument("target")
    command.add_argument("--scope", required=True, help="allowlist file containing domains, IP/CIDR, or local paths")
    command.add_argument("--authorization-ref", help="ticket/program/permission reference")
    command.add_argument("--authorized", action="store_true", help="confirm authorization for this specific target")
    command.add_argument("--active", action="store_true", help="enable separately gated active modules")
    command.add_argument("--active-authorized", action="store_true", help="second confirmation for active operations")
    command.add_argument("--active-authorization-ref")
    command.add_argument("--audit-log", default=".cygnus/audit.jsonl")
    command.add_argument("--timeout", type=float, default=3.0)
    command.add_argument("--repository-path", help="operator-provided local repository for static secret patterns")
    command.add_argument("--format", choices=("markdown", "json"), default="markdown")
    command.add_argument("--output")
    return command


def _interactive_authorization(args) -> None:
    if not args.authorized and sys.stdin.isatty():
        response = input(f"Authorization gate: do you have explicit permission for {args.target}? Type 'yes': ")
        args.authorized = response.strip().lower() == "yes"
    if args.authorized and not args.authorization_ref and sys.stdin.isatty():
        args.authorization_ref = input("Authorization/scope reference: ").strip()
    if args.active and not args.active_authorized and sys.stdin.isatty():
        response = input("Separate active-operation confirmation required. Type 'ACTIVE-AUTHORIZED': ")
        args.active_authorized = response.strip() == "ACTIVE-AUTHORIZED"


async def execute(args) -> int:
    # Audit begins before validation so denied/out-of-scope attempts are retained.
    outcome = "denied"
    try:
        reference = require_authorization(args.authorized, args.authorization_ref, args.active, args.active_authorized)
        scope = Scope.from_file(args.scope)
        if not scope.permits(args.target):
            raise AuthorizationError(f"target is outside allowlist scope: {args.target}")
        log_attempt(args.audit_log, args.target, reference, "authorized-in-scope")
        profile, mode = await Fingerprinter(args.timeout).run(args.target)
        print(f"\nOperating mode auto-detected from runtime access: {mode.value}\n", file=sys.stderr)
        context = ScanContext(mode, reference, args.active, args.active_authorization_ref, args.timeout, repository_path=args.repository_path)
        report = await ScanEngine().run(profile, context)
        rendered = to_json(report) if args.format == "json" else to_markdown(report)
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print(rendered)
        outcome = "completed"
        return 0
    except (AuthorizationError, OSError, ValueError) as exc:
        print(f"CYGNUS blocked scan: {exc}", file=sys.stderr)
        return 2
    finally:
        if outcome != "completed":
            log_attempt(args.audit_log, args.target, args.authorization_ref, outcome)


def main() -> None:
    print(BANNER, flush=True)  # always first visible output, before the gate
    args = parser().parse_args()
    _interactive_authorization(args)
    raise SystemExit(asyncio.run(execute(args)))


if __name__ == "__main__":
    main()
