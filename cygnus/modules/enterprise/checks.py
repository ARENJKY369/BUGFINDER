from __future__ import annotations

import json
from importlib.resources import files
from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import http_request


class EnterpriseVersionCVE:
    name = "enterprise.version_cve"
    applies_to = frozenset({AssetType.CMS, AssetType.CRM, AssetType.ERP})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        text = (response.text + " " + response.headers.get("x-generator", "")).lower()
        cache = json.loads(files("cygnus").joinpath("data/cve_cache.json").read_text(encoding="utf-8"))
        findings = []
        for entry in cache["entries"]:
            version = next((v for v in entry["versions"] if entry["product"] in text and v.lower() in text), None)
            if not version:
                continue
            findings.append(FindingCandidate(
                f"Published application version matches {entry['id']}", AssetType.CMS, target.normalized_target,
                [Evidence("http-response", f"Exact product/version match: {entry['product']} {version}", response.capture(), request=f"GET {target.normalized_target}", source=entry["source"], strength="moderate")],
                "The application publishes a version present in the local NVD-derived cache.",
                "This version correlation requires manual confirmation of patch/backport state.",
                "Upgrade using vendor guidance or document the applicable backported patch.", impact="high",
                cve={"id": entry["id"], "source": entry["source"], "dataset_updated": cache["metadata"]["last_updated"]}, tags={"version-cve-match"},
            ))
        return findings


MODULES = [EnterpriseVersionCVE()]
