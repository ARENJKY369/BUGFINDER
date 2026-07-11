from __future__ import annotations

import json
import re
from importlib.resources import files
from urllib.parse import urlparse

from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import tcp_capture

NETWORK_TYPES = frozenset({AssetType.SSH, AssetType.FTP, AssetType.VPN, AssetType.RDP, AssetType.EMAIL, AssetType.DATABASE, AssetType.NETWORK_DEVICE})
PORTS = {AssetType.FTP: 21, AssetType.SSH: 22, AssetType.EMAIL: 25, AssetType.RDP: 3389}


def endpoint(profile: AssetProfile, kind: AssetType) -> tuple[str, int]:
    parsed = urlparse(profile.normalized_target)
    return parsed.hostname or profile.normalized_target, parsed.port or PORTS.get(kind, 0)


class ServiceBanner:
    name = "network.banner_configuration"
    applies_to = NETWORK_TYPES
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        kind = next((item for item in target.types if item in NETWORK_TYPES), None)
        if not kind:
            return []
        host, port = endpoint(target, kind)
        if not port:
            return []
        banner = await tcp_capture(host, port, ctx.timeout, b"FEAT\r\n" if kind == AssetType.FTP else None)
        text = banner.decode("utf-8", "replace")
        if not text:
            return []
        findings: list[FindingCandidate] = []
        if kind == AssetType.FTP and re.search(r"anonymous\s+(?:login\s+)?(?:allowed|enabled|ok)", text, re.I):
            findings.append(FindingCandidate(
                "FTP service advertises anonymous access", kind, f"{host}:{port}",
                [Evidence("tcp-banner", "FTP banner/feature response advertises anonymous access", text, request=f"CONNECT {host}:{port}; FEAT", strength="moderate")],
                "The service configuration announces anonymous access.",
                "Anonymous users may be able to retrieve exposed files; no login was attempted.",
                "Disable anonymous FTP or strictly constrain it to intended read-only public data.", impact="limited", tags={"anonymous-access"},
            ))
        findings.extend(_cve_matches(kind, f"{host}:{port}", text))
        return findings


def _cve_matches(kind: AssetType, component: str, banner: str) -> list[FindingCandidate]:
    cache = json.loads(files("cygnus").joinpath("data/cve_cache.json").read_text(encoding="utf-8"))
    lower = banner.lower()
    output = []
    for entry in cache["entries"]:
        if entry["product"] not in lower:
            continue
        version = next((version for version in entry["versions"] if version.lower() in lower), None)
        if not version:
            continue
        cve = {"id": entry["id"], "source": entry["source"], "dataset_updated": cache["metadata"]["last_updated"]}
        output.append(FindingCandidate(
            f"Banner version matches {entry['id']}", kind, component,
            [Evidence("tcp-banner", f"Exact cached vulnerable version match: {entry['product']} {version}", banner, source=entry["source"], strength="moderate")],
            "The exposed service reports an exact version listed in the local NVD-derived cache.",
            "Version matching is not proof that the vulnerable code path is reachable; verify vendor backports.",
            "Apply the vendor update and suppress only after confirming a backported fix.", impact="high", cve=cve, tags={"version-cve-match"},
        ))
    return output


MODULES = [ServiceBanner()]
