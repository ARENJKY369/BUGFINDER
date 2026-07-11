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

class OpenAPIObjectAuthorizationSurface:
    name = "web.openapi_object_authorization"
    applies_to = frozenset({AssetType.API_DOCS})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        import json
        from urllib.parse import urljoin
        url = urljoin(target.normalized_target, "/openapi.json")
        response = await http_request(url, ctx.timeout)
        if response.status != 200:
            return []
        try:
            document = json.loads(response.text)
        except ValueError:
            return []
        for path, definition in document.get("paths", {}).items():
            if "{" not in path or not isinstance(definition, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete"):
                operation = definition.get(method)
                if isinstance(operation, dict) and operation.get("security", "inherited") == []:
                    capture = response.capture() + f"\nMatched operation: {method.upper()} {path}; security: []"
                    return [FindingCandidate(
                        "Object-level authorization review point declared by OpenAPI", AssetType.API_DOCS, url,
                        [Evidence("http-response", "Object-reference operation explicitly has no OpenAPI security requirement", capture, request=f"GET {url}", strength="weak")],
                        "The API contract explicitly marks an object-reference operation with an empty security requirement.",
                        "This is not claimed as IDOR. Using authorized test identities, verify server-side ownership and role enforcement.",
                        "Require authentication in the contract and enforce object-level authorization on every operation.",
                        impact="high", tags={"idor-indicator", "public-interface"},
                    )]
        return []


class SessionCookieAttributes:
    name = "web.session_cookie_attributes"
    applies_to = WEB_TYPES
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        response = await http_request(target.normalized_target, ctx.timeout)
        # http_request redacts set-cookie values in capture, but headers dict retains original for analysis
        # Check transport layer for raw Set-Cookie if available via headers (case-insensitive)
        set_cookie = response.headers.get("set-cookie", "") or response.headers.get("Set-Cookie", "")
        # Also inspect raw capture for cookie attribute hints (redacted values still show attributes)
        capture_lower = response.capture().lower()
        if "set-cookie" not in capture_lower and not set_cookie:
            return []
        # Analyze attributes
        cookie_str = set_cookie.lower() if set_cookie else capture_lower
        missing = []
        # session-like cookie detection
        if any(token in cookie_str for token in ("session", "sessid", "auth", "token", "set-cookie")):
            if "secure" not in cookie_str:
                missing.append("Secure")
            if "httponly" not in cookie_str:
                missing.append("HttpOnly")
            if "samesite" not in cookie_str:
                missing.append("SameSite")
        if not missing:
            return []
        # Choose an asset type present in the profile
        asset_type = next((t for t in (AssetType.WEB_SERVER, AssetType.WEBSITE, AssetType.WEB_APPLICATION, AssetType.API) if t in target.types), AssetType.WEB_SERVER)
        return [FindingCandidate(
            "Session cookie missing secure attributes", asset_type, target.normalized_target,
            [Evidence("http-response", f"Set-Cookie missing attributes: {', '.join(missing)}", response.capture(), request=f"GET {target.normalized_target}", strength="moderate")],
            "Session management cookie does not enforce Secure, HttpOnly, and SameSite protections.",
            "Cookies without these attributes are exposed to network interception, client-side script access, and cross-site request forgery.",
            "Set Secure, HttpOnly, and SameSite=Lax or Strict on all session cookies; scope cookie paths narrowly.",
            impact="limited", tags={"session-cookie"},
        )]


class VerboseErrorDisclosure:
    name = "web.verbose_error_disclosure"
    applies_to = WEB_TYPES
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        # Passive check: inspect baseline response for verbose error signatures
        response = await http_request(target.normalized_target, ctx.timeout)
        body_lower = response.text.lower()
        error_indicators = [
            "traceback (most recent call last)",
            "stack trace",
            "exception in thread",
            "fatal error",
            "uncaught exception",
            "sql syntax",
            "ora-",
            "warning: ",
            "notice: ",
            "/var/www/",
            "c:\\inetpub\\",
            "node_modules",
            "at java.",
            "at org.",
            "php fatal error",
        ]
        matched = [indicator for indicator in error_indicators if indicator in body_lower]
        if not matched:
            return []
        asset_type = next((t for t in (AssetType.WEB_SERVER, AssetType.WEBSITE, AssetType.WEB_APPLICATION, AssetType.API) if t in target.types), AssetType.WEB_SERVER)
        return [FindingCandidate(
            "Verbose error information disclosure", asset_type, target.normalized_target,
            [Evidence("http-response", f"Response contains verbose error indicator(s): {', '.join(matched[:3])}", response.capture(), request=f"GET {target.normalized_target}", strength="moderate")],
            "Application response exposes stack traces, file paths, or framework error messages.",
            "Verbose errors aid attackers in mapping internal architecture and crafting targeted exploits.",
            "Disable debug output in production; centralize error handling and log server-side only.",
            impact="limited", tags={"error-disclosure"},
        )]


class OpenRedirectCheck:
    name = "web.open_redirect"
    applies_to = frozenset({AssetType.WEB_APPLICATION, AssetType.WEBSITE, AssetType.AUTH})
    requires_active = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        # Passive open-redirect test using common redirect parameters with an external safe canary URL
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
        canary = "https://cygnus-redirect-canary.example/"
        redirect_params = ["next", "redirect", "url", "return", "returnUrl", "redirect_uri", "continue", "dest", "destination"]
        parsed = urlparse(target.normalized_target)
        base_query = parse_qsl(parsed.query, keep_blank_values=True)
        for param in redirect_params:
            test_query = base_query + [(param, canary)]
            test_url = urlunparse(parsed._replace(query=urlencode(test_query)))
            response = await http_request(test_url, ctx.timeout)
            # Check for redirect status via headers (Location) or meta refresh / body reflection
            location = response.headers.get("location", "")
            body_lower = response.text.lower()
            # Evidence: Location header points to canary, or body contains canary unvalidated
            if canary in location or canary in body_lower or "cygnus-redirect-canary.example" in body_lower:
                asset_type = next((t for t in (AssetType.WEB_SERVER, AssetType.WEBSITE, AssetType.WEB_APPLICATION, AssetType.AUTH, AssetType.API) if t in target.types), AssetType.WEB_SERVER)
                return [FindingCandidate(
                    "Open redirect parameter detected", asset_type, test_url,
                    [Evidence("http-response", f"Redirect parameter '{param}' reflected external URL in Location/body", response.capture(), request=f"GET {test_url}", strength="moderate")],
                    "A URL parameter commonly used for post-action navigation reflects an arbitrary external destination.",
                    "Attackers can craft phishing links that abuse trusted domain redirects to external sites.",
                    "Validate redirect destinations against an explicit allowlist; use relative paths or signed redirect tokens.",
                    impact="limited", tags={"open-redirect"},
                )]
        return []


MODULES = [SecurityHeaders(), CorsPolicy(), ReflectionMarker(), ObjectAuthorizationIndicator(), UnauthenticatedAdminIndicator(), OpenAPIObjectAuthorizationSurface(), SessionCookieAttributes(), VerboseErrorDisclosure(), OpenRedirectCheck()]
