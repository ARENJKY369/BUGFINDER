from __future__ import annotations

from urllib.parse import urljoin
from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import http_request


class ExposedControlPlane:
    name = "containers.exposed_control_plane"
    applies_to = frozenset({AssetType.KUBERNETES, AssetType.DOCKER, AssetType.CONTAINER})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        kind = AssetType.KUBERNETES if AssetType.KUBERNETES in target.types else AssetType.DOCKER
        path = "/version" if kind == AssetType.KUBERNETES else "/_ping"
        url = urljoin(target.normalized_target.rstrip("/") + "/", path.lstrip("/"))
        response = await http_request(url, ctx.timeout)
        body = response.text.lower()
        positive = response.status == 200 and ((kind == AssetType.KUBERNETES and ("gitversion" in body or "major" in body)) or (kind == AssetType.DOCKER and body.strip() == "ok"))
        if not positive:
            return []
        return [FindingCandidate(
            "Container control-plane endpoint exposed", kind, url,
            [Evidence("http-response", f"Unauthenticated {kind.value} identity endpoint responded", response.capture(), request=f"GET {url}", strength="moderate")],
            "A control-plane identity endpoint is reachable without a network or authentication boundary.",
            "This detection-only check did not attempt mutation; manually assess authorization on sensitive operations.",
            "Bind the API to a management network and require strong client authentication.", impact="high", tags={"exposed-control-plane"},
        )]


MODULES = [ExposedControlPlane()]
