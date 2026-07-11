"""Orchestration, evidence validation, scoring, and explicit chain rules."""
from __future__ import annotations

import hashlib

from .models import Finding, FindingCandidate, Mode, ModuleResult, ScanContext, ScanReport
from .plugin import discover_modules

SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CHAIN_RULES = [
    {
        "name": "Browser policy weakness amplifies confirmed script injection",
        "requires": ("missing-security-headers", "confirmed-script-injection"),
        "impact": "A confirmed script injection has fewer browser policy constraints.",
    }
]


class ScanEngine:
    def __init__(self, modules=None):
        self.modules = modules if modules is not None else discover_modules()

    async def run(self, profile, ctx: ScanContext) -> ScanReport:
        results: list[ModuleResult] = []
        candidates: list[FindingCandidate] = []
        for module in self.modules:
            intersection = profile.types & module.applies_to
            if not intersection:
                results.append(ModuleResult(module.name, "skipped", "not applicable to detected asset types"))
                continue
            if module.requires_active and not ctx.active:
                results.append(ModuleResult(module.name, "skipped", "active authorization not supplied"))
                continue
            if ctx.mode == Mode.OFFLINE_STATIC and not getattr(module, "supports_offline", False):
                results.append(ModuleResult(module.name, "skipped", "live protocol unavailable in OFFLINE-STATIC mode"))
                continue
            try:
                found = await module.run(profile, ctx)
                valid = [item for item in found if item.evidence and all(ev.captured.strip() for ev in item.evidence)]
                results.append(ModuleResult(module.name, "ran", f"completed with {len(valid)} evidence-backed candidate(s)", valid))
                candidates.extend(valid)
            except Exception as exc:
                results.append(ModuleResult(module.name, "error", f"{type(exc).__name__}: {str(exc)[:240]}"))

        findings = [self._score(candidate, ctx.mode, index) for index, candidate in enumerate(candidates, 1)]
        confirmed = [item for item in findings if item.status == "CONFIRMED"]
        manual = [item for item in findings if item.status != "CONFIRMED"]
        chains = self._chains(confirmed)
        return ScanReport(ctx.mode, profile, ctx.authorization_reference, results, confirmed, manual, chains, self._next_steps(confirmed, manual, results))

    @staticmethod
    def _score(candidate: FindingCandidate, mode: Mode, index: int) -> Finding:
        weakest = min(({"weak": 0, "moderate": 1, "strong": 2}.get(ev.strength, 0) for ev in candidate.evidence), default=0)
        confidence = ("Low", "Medium", "High")[weakest]
        impact_base = {"limited": "Low", "high": "High", "critical": "Critical"}.get(candidate.impact, "Low")
        severity = impact_base
        if weakest == 0 and SEVERITY_ORDER[severity] > SEVERITY_ORDER["Medium"]:
            severity = "Medium"
        if weakest == 1 and severity == "Critical":
            severity = "High"
        uncertain = bool(candidate.tags & {"version-cve-match", "reflection", "default-credential-indicator", "public-interface"})
        status = "STATIC/UNCONFIRMED" if mode == Mode.OFFLINE_STATIC else ("NEEDS MANUAL VERIFICATION" if weakest == 0 or uncertain else "CONFIRMED")
        digest = hashlib.sha256((candidate.name + candidate.component + candidate.evidence[0].captured).encode()).hexdigest()[:10]
        return Finding(
            f"CYG-{digest}", candidate.name, candidate.asset_type, severity, confidence, status,
            candidate.component, candidate.evidence, candidate.root_cause, candidate.exploitation_vector,
            candidate.remediation, candidate.cve, candidate.tags,
        )

    @staticmethod
    def _chains(confirmed: list[Finding]) -> list[dict]:
        tags = {tag: finding for finding in confirmed for tag in finding.tags}
        chains = []
        for rule in CHAIN_RULES:
            if all(tag in tags for tag in rule["requires"]):
                chains.append({"name": rule["name"], "finding_ids": [tags[tag].id for tag in rule["requires"]], "impact": rule["impact"]})
        return chains

    @staticmethod
    def _next_steps(confirmed: list[Finding], manual: list[Finding], results: list[ModuleResult]) -> list[str]:
        steps = []
        for finding in manual:
            if "reflection" in finding.tags:
                steps.append(f"Review the encoding context of the reflected marker at {finding.component}; no executable payload was sent.")
            elif "version-cve-match" in finding.tags:
                steps.append(f"Confirm vendor backport/patch state for {finding.cve['id']} on {finding.component}.")
            elif "public-interface" in finding.tags:
                steps.append(f"Verify operation-level authorization on the interface at {finding.component}.")
        errors = [result.module for result in results if result.status == "error"]
        if errors:
            steps.append("Re-run failed protocol checks after validating reachability: " + ", ".join(errors))
        if not steps and confirmed:
            steps.append("Retest the identified components after applying the finding-specific remediations.")
        if not steps:
            steps.append("No positive evidence was captured; expand authorized scope or provide source/repository material for deeper static analysis.")
        return list(dict.fromkeys(steps))
