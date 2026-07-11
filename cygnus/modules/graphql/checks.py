from __future__ import annotations
import json
from urllib.parse import urljoin,urlparse
from cygnus.core.models import AssetProfile,AssetType,Evidence,FindingCandidate,ScanContext
from cygnus.core.transport import http_request

class GraphQLIntrospection:
    name="graphql.introspection"
    applies_to=frozenset({AssetType.GRAPHQL})
    requires_active=False
    async def run(self,target:AssetProfile,ctx:ScanContext)->list[FindingCandidate]:
        parsed=urlparse(target.normalized_target)
        url=target.normalized_target if "graphql" in parsed.path.lower() else urljoin(target.normalized_target,"/graphql")
        payload=json.dumps({"query":"query CygnusSchemaProbe { __schema { queryType { name } } }"}).encode()
        response=await http_request(url,ctx.timeout,{"Content-Type":"application/json"},"POST",payload)
        if response.status!=200 or '"__schema"' not in response.text:return []
        return [FindingCandidate("GraphQL schema introspection is publicly reachable",AssetType.GRAPHQL,url,
          [Evidence("http-response","Unauthenticated schema probe returned __schema data",response.capture(),request=f"POST {url}",strength="weak")],
          "The production GraphQL endpoint exposes schema introspection without an access boundary.",
          "An unauthenticated party can enumerate schema structure; this is not treated as direct exploitation.",
          "Disable public introspection when unnecessary and enforce authorization on every resolver.",impact="limited",tags={"public-interface"})]
MODULES=[GraphQLIntrospection()]
