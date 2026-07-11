from __future__ import annotations

from urllib.parse import urlparse
from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import tcp_capture


class DefaultCredentialIndicator:
    name = "iot.default_credential_indicator"
    applies_to = frozenset({AssetType.IOT, AssetType.NETWORK_DEVICE})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        parsed = urlparse(target.normalized_target)
        host, port = parsed.hostname, parsed.port or 80
        banner = await tcp_capture(host or "", port, ctx.timeout)
        text = banner.decode("utf-8", "replace")
        markers = ("default password", "default credentials", "password: admin")
        marker = next((m for m in markers if m in text.lower()), None)
        if not marker:
            return []
        return [FindingCandidate(
            "Device advertises a default-credential indicator", AssetType.IOT, f"{host}:{port}",
            [Evidence("tcp-banner", "Service content contains a default-credential instruction", text, request=f"CONNECT {host}:{port}", strength="weak")],
            "Device onboarding or service content references vendor-default credentials.",
            "Manual verification is required; CYGNUS did not submit any credential.",
            "Complete secure onboarding, rotate defaults, and disable remote administration where unnecessary.", impact="limited", tags={"default-credential-indicator"},
        )]


MODULES = [DefaultCredentialIndicator()]
