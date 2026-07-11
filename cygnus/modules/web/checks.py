from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cygnus.core.models import AssetProfile, AssetType, Evidence, FindingCandidate, ScanContext
from cygnus.core.transport import http_request

WEB_TYPES = frozenset({AssetType.WEB_APPLICATION, AssetType.WEBSITE, AssetType.API, AssetType.GRAPHQL, AssetType.WEB_SERVER, AssetType.AUTH, AssetType.ADMIN_PANEL})


class SecurityHeaders:
    name = "web.security_headers"
    applies_to = WEB_TYPES
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        required = {"content-security-policy", "x-content-type-options", "referrer-policy"}
        missing = sorted(required - response.headers.keys())
        if not missing:
            return []
        return [FindingCandidate(
            "Missing browser security headers", AssetType.WEB_SERVER, target.normalized_target,
            [Evidence("http-response", f"Response omitted: {', '.join(missing)}", response.capture(), request=f"GET {target.normalized_target}", strength="moderate")],
            "The server response does not set defense-in-depth browser policies.",
            "A separate content-injection weakness could have greater browser impact.",
            "Set the listed headers with application-appropriate restrictive values.", impact="limited", tags={"missing-security-headers"},
        )]


class CorsPolicy:
    name = "web.cors"
    applies_to = WEB_TYPES
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        origin = "https://cygnus-invalid.example"
        response = await http_request(target.normalized_target, ctx.timeout, {"Origin": origin})
        allow = response.headers.get("access-control-allow-origin", "")
        credentials = response.headers.get("access-control-allow-credentials", "").lower()
        vulnerable = allow == origin or (allow == "*" and credentials == "true")
        if not vulnerable:
            return []
        return [FindingCandidate(
            "Untrusted cross-origin access allowed", AssetType.WEB_APPLICATION, target.normalized_target,
            [Evidence("http-response", "Server authorized a synthetic untrusted Origin", response.capture(), request=f"GET {target.normalized_target}\nOrigin: {origin}")],
            "CORS policy reflects arbitrary origins or combines wildcard origin with credentials.",
            "A malicious origin can issue browser requests and potentially read responses.",
            "Use a strict origin allowlist and never combine wildcard origin with credentials.", impact="high", tags={"cors"},
        )]


class ReflectionMarker:
    name = "web.reflection_marker"
    applies_to = frozenset({AssetType.WEB_APPLICATION, AssetType.WEBSITE, AssetType.API})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        marker = "CYGNUS_REFLECT_7f3a"
        parsed = urlparse(target.normalized_target)
        query = parse_qsl(parsed.query, keep_blank_values=True) + [("cygnus_probe", marker)]
        url = urlunparse(parsed._replace(query=urlencode(query)))
        response = await http_request(url, ctx.timeout)
        if marker not in response.text:
            return []
        return [FindingCandidate(
            "User-controlled marker reflected in response", AssetType.WEB_APPLICATION, url,
            [Evidence("http-response", "Harmless marker returned in response body", response.capture(), request=f"GET {url}", strength="weak")],
            "Request data is reflected without an observed output transformation.",
            "Manual contextual review is needed; reflection alone does not prove script execution or injection.",
            "Apply context-aware output encoding and validate expected parameter formats.", impact="limited", tags={"reflection"},
        )]


class ObjectAuthorizationIndicator:
    name = "web.object_authorization_indicators"
    applies_to = frozenset({AssetType.API, AssetType.GRAPHQL})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        body = response.text.lower()
        identifiers = next((key for key in ('"user_id"', '"account_id"', '"owner_id"') if key in body), None)
        if response.status != 200 or not identifiers:
            return []
        return [FindingCandidate(
            "Object identifier exposed for authorization review", AssetType.API, target.normalized_target,
            [Evidence("http-response", f"API response contains {identifiers}", response.capture(), request=f"GET {target.normalized_target}", strength="weak")],
            "An object identifier is present in an unauthenticated or baseline API response; object-level authorization was not tested.",
            "A reviewer should compare responses using two explicitly provided test accounts; CYGNUS does not alter identifiers automatically.",
            "Enforce server-side object ownership/entitlement checks on every object operation.", impact="limited", tags={"idor-indicator"},
        )]


class UnauthenticatedAdminIndicator:
    name = "web.auth_exposure"
    applies_to = frozenset({AssetType.ADMIN_PANEL, AssetType.AUTH, AssetType.API_DOCS})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        if response.status != 200 or not ({AssetType.ADMIN_PANEL, AssetType.API_DOCS} & target.types):
            return []
        return [FindingCandidate(
            "Administrative or API documentation surface reachable without authentication", AssetType.ADMIN_PANEL, target.normalized_target,
            [Evidence("http-response", "Unauthenticated request reached a sensitive interface signature", response.capture(), request=f"GET {target.normalized_target}", strength="weak")],
            "A sensitive interface is publicly reachable; authorization of privileged actions is not established.",
            "Review whether exposed metadata or unauthenticated operations expand attack surface.",
            "Restrict the interface by authentication and network policy if it is not intentionally public.", impact="limited", tags={"public-interface"},
        )]


MODULES = [SecurityHeaders(), CorsPolicy(), ReflectionMarker(), ObjectAuthorizationIndicator(), UnauthenticatedAdminIndicator()]
