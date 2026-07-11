from __future__ import annotations
import json
from urllib.parse import urljoin,urlparse
from cygnus.core.models import AssetProfile,AssetType,Evidence,FindingCandidate,ScanContext
from cygnus.core.transport import http_request

class OpenIDMetadataPolicy:
    name="auth.openid_metadata_policy"
    applies_to=frozenset({AssetType.OAUTH_SSO,AssetType.IDENTITY_PROVIDER})
    requires_active=False
    async def run(self,target:AssetProfile,ctx:ScanContext)->list[FindingCandidate]:
        url=urljoin(target.normalized_target,"/.well-known/openid-configuration")
        response=await http_request(url,ctx.timeout)
        if response.status!=200:return []
        try:metadata=json.loads(response.text)
        except ValueError:return []
        issuer=str(metadata.get("issuer","")); findings=[]
        if issuer and urlparse(issuer).scheme!="https":
            findings.append(FindingCandidate("OpenID issuer uses insecure transport",AssetType.IDENTITY_PROVIDER,url,
              [Evidence("http-response","Discovery metadata advertises a non-HTTPS issuer",response.capture(),request=f"GET {url}")],
              "Identity metadata publishes an issuer over insecure transport.","Clients following insecure identity endpoints may expose authorization traffic to interception.",
              "Publish and enforce HTTPS identity endpoints and update relying-party configuration.",impact="high",tags={"openid-policy"}))
        algorithms=[str(x).lower() for x in metadata.get("id_token_signing_alg_values_supported",[])]
        if "none" in algorithms:
            findings.append(FindingCandidate("OpenID metadata advertises unsigned ID tokens",AssetType.IDENTITY_PROVIDER,url,
              [Evidence("http-response","Supported ID-token algorithms include none",response.capture(),request=f"GET {url}",strength="weak")],
              "Provider metadata advertises an unsigned-token algorithm.","Manual verification is required to determine whether relying parties accept unsigned tokens.",
              "Remove `none` and enforce signature, issuer, audience, and lifetime validation.",impact="high",tags={"openid-policy","public-interface"}))
        return findings
MODULES=[OpenIDMetadataPolicy()]
