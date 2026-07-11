from __future__ import annotations

from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import http_request


class PublicObjectStorage:
    name = "cloud.public_storage"
    applies_to = frozenset({AssetType.CLOUD, AssetType.OBJECT_STORAGE})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        body = response.text.lower()
        listing = response.status == 200 and any(marker in body for marker in ("<listbucketresult", '"contents"', "<enumerationresults"))
        if not listing:
            return []
        return [FindingCandidate(
            "Object storage permits unauthenticated listing", AssetType.OBJECT_STORAGE, target.normalized_target,
            [Evidence("http-response", "Unauthenticated storage endpoint returned a listing structure", response.capture(), request=f"GET {target.normalized_target}")],
            "The bucket/container listing policy allows public principals.",
            "An unauthenticated party can enumerate object names and metadata.",
            "Remove public list permission and grant least-privilege access to operator-provided identities.", impact="high", tags={"public-storage-listing"},
        )]


MODULES = [PublicObjectStorage()]
