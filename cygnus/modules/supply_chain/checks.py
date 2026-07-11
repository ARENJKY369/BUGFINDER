from __future__ import annotations

import re
from pathlib import Path
from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import http_request

PATTERNS = {
    "Private key material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access-key identifier": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
}


class PublicDevelopmentSurface:
    name = "supply_chain.public_exposure"
    applies_to = frozenset({AssetType.GIT, AssetType.CICD, AssetType.PACKAGE_REGISTRY, AssetType.ARTIFACT_REPOSITORY})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        if response.status != 200:
            return []
        return [FindingCandidate(
            "Development or delivery interface publicly reachable", next(iter(target.types & self.applies_to)), target.normalized_target,
            [Evidence("http-response", "Unauthenticated request reached a development/delivery interface", response.capture(), request=f"GET {target.normalized_target}", strength="weak")],
            "A source, CI/CD, or package interface is internet reachable; repository/job authorization is not established.",
            "Manually verify intended visibility and operation-level authorization without guessing credentials.",
            "Restrict private interfaces and require strong authentication; retain public access only when intentional.", impact="limited", tags={"public-interface"},
        )]


class RepositorySecretPatterns:
    name = "supply_chain.secret_patterns"
    applies_to = frozenset({AssetType.GIT, AssetType.CICD, AssetType.PACKAGE_REGISTRY})
    requires_active = False
    supports_offline = True

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        root = Path(ctx.repository_path) if ctx.repository_path else None
        if not root or not root.exists():
            return []
        findings = []
        paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
        for path in paths[:5000]:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
            except OSError:
                continue
            for label, pattern in PATTERNS.items():
                match = pattern.search(text)
                if not match:
                    continue
                redacted = match.group(0)[:6] + "…REDACTED…" + match.group(0)[-4:]
                findings.append(FindingCandidate(
                    f"{label} found in operator-provided repository", AssetType.GIT, str(path),
                    [Evidence("static-source", f"Pattern match in {path}", redacted, request="local repository read", strength="moderate")],
                    "Credential-like material is committed in source content.",
                    "If valid, a party with repository access could impersonate the credential owner.",
                    "Revoke and rotate the secret, remove it from history, and enable pre-commit secret scanning.", impact="high", tags={"secret-pattern"},
                ))
        return findings


MODULES = [PublicDevelopmentSurface(), RepositorySecretPatterns()]
