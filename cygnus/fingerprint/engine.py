"""Evidence-producing, protocol-aware asset fingerprinting."""
from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

from cygnus.core.models import AssetClassification, AssetProfile, AssetType, Evidence, Mode
from cygnus.core.transport import http_request, tcp_capture

PORT_TYPES = {
    21: AssetType.FTP, 22: AssetType.SSH, 25: AssetType.EMAIL, 53: AssetType.DNS,
    80: AssetType.WEB_SERVER, 443: AssetType.WEB_SERVER, 445: AssetType.NETWORK_DEVICE,
    2375: AssetType.DOCKER, 2376: AssetType.DOCKER, 3000: AssetType.WEB_APPLICATION,
    3306: AssetType.DATABASE, 3389: AssetType.RDP, 5432: AssetType.DATABASE,
    6443: AssetType.KUBERNETES, 8080: AssetType.WEB_SERVER, 8443: AssetType.WEB_SERVER,
    10250: AssetType.KUBERNETES,
}


class Fingerprinter:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def run(self, target: str) -> tuple[AssetProfile, Mode]:
        path = Path(target)
        if path.exists():
            return self._file_profile(path), Mode.OFFLINE_STATIC

        normalized, host, explicit_port = self._normalize(target)
        classifications: dict[AssetType, list[Evidence]] = {}
        signals: dict[str, object] = {}

        def add(kind: AssetType, evidence: Evidence) -> None:
            classifications.setdefault(kind, []).append(evidence)

        try:
            addresses = sorted({item[4][0] for item in await asyncio.to_thread(socket.getaddrinfo, host, None)})
            dns_ev = Evidence("dns", f"{host} resolved", ", ".join(addresses), request=f"getaddrinfo({host})")
            signals["addresses"] = addresses
            add(AssetType.IP_ADDRESS if self._is_ip(host) else AssetType.DOMAIN, dns_ev)
            if not self._is_ip(host) and host.count(".") > 1:
                add(AssetType.SUBDOMAIN, dns_ev)
        except OSError as exc:
            signals["dns_error"] = str(exc)

        parsed = urlparse(normalized)
        if parsed.scheme in {"http", "https"}:
            try:
                exchange = await http_request(normalized, self.timeout)
                signals["http"] = {"status": exchange.status, "headers": exchange.headers, "body": exchange.text[:8192], "url": exchange.url}
                ev = Evidence("http", "HTTP endpoint responded", exchange.capture(), request=f"GET {normalized}")
                add(AssetType.WEB_SERVER, ev)
                content_type = exchange.headers.get("content-type", "")
                body_lower = exchange.text.lower()
                if "text/html" in content_type or "<html" in body_lower:
                    add(AssetType.WEBSITE, ev)
                    if any(marker in body_lower for marker in ("<form", "window.__", "webpack", "react")):
                        add(AssetType.WEB_APPLICATION, ev)
                if "application/json" in content_type or body_lower.lstrip().startswith(("{", "[")):
                    add(AssetType.API, ev)
                if "graphql" in parsed.path.lower():
                    add(AssetType.GRAPHQL, Evidence("url-signature", "GraphQL path signature matched", parsed.path, request=f"GET {normalized}"))
                host_lower = host.lower()
                if any(marker in host_lower for marker in ("s3.amazonaws.com", ".s3.", "blob.core.windows.net", "storage.googleapis.com")):
                    add(AssetType.CLOUD, Evidence("hostname-signature", "Cloud storage hostname matched", host, request=f"DNS/HTTP {host}"))
                    add(AssetType.OBJECT_STORAGE, Evidence("hostname-signature", "Object storage hostname matched", host, request=f"DNS/HTTP {host}"))
                signatures = {
                    AssetType.GRAPHQL: ("graphql", "__schema"),
                    AssetType.API_DOCS: ("swagger", "openapi"),
                    AssetType.ADMIN_PANEL: ("admin dashboard", "sign in to admin"),
                    AssetType.AUTH: ("type=\"password\"", "oauth", "saml"),
                    AssetType.KUBERNETES: ("kubernetes dashboard",),
                    AssetType.DOCKER: ("docker api",),
                    AssetType.CMS: ("wp-content", "drupal", "joomla"),
                    AssetType.CICD: ("jenkins", "gitlab", "teamcity"),
                    AssetType.GIT: ("github repository", "git repository", "gitlab"),
                    AssetType.PACKAGE_REGISTRY: ("package registry", "npm registry", "container registry"),
                }
                for asset_type, markers in signatures.items():
                    matched = next((marker for marker in markers if marker in body_lower), None)
                    if matched:
                        add(asset_type, Evidence("http-signature", f"Matched {asset_type.value} signature", matched, request=f"GET {normalized}"))
            except Exception as exc:
                signals["http_error"] = f"{type(exc).__name__}: {exc}"
            # Bounded read-only discovery improves classification without crawling.
            base = f"{parsed.scheme}://{parsed.netloc}"
            discovery_paths = (
                ("robots", "/robots.txt"),
                ("security_txt", "/.well-known/security.txt"),
                ("openid", "/.well-known/openid-configuration"),
                ("openapi", "/openapi.json"),
            )
            async def discover(label: str, path: str):
                try:
                    return label, path, await http_request(base + path, self.timeout)
                except Exception:
                    return label, path, None
            for label, path, discovery in await asyncio.gather(*(discover(*item) for item in discovery_paths)):
                if not discovery or discovery.status >= 400 or not discovery.text.strip():
                    continue
                signals[label] = {"status": discovery.status, "body": discovery.text[:2048]}
                lower = discovery.text.lower()
                dev = Evidence("http-discovery", f"{path} returned recognizable metadata", discovery.capture(), request=f"GET {base + path}")
                if label == "openid" and '"issuer"' in lower:
                    add(AssetType.OAUTH_SSO, dev); add(AssetType.IDENTITY_PROVIDER, dev); add(AssetType.AUTH, dev)
                if label == "openapi" and any(marker in lower for marker in ('"openapi"', '"swagger"')):
                    add(AssetType.API, dev); add(AssetType.API_DOCS, dev)

        port = explicit_port or (443 if parsed.scheme == "https" else 80)
        protocol_type = {"ftp": AssetType.FTP, "sftp": AssetType.FTP, "ssh": AssetType.SSH, "rdp": AssetType.RDP, "vpn": AssetType.VPN}.get(parsed.scheme, PORT_TYPES.get(port))
        if protocol_type and protocol_type not in classifications:
            try:
                banner = await tcp_capture(host, port, self.timeout)
                capture = banner.decode("utf-8", "replace") or f"TCP connection accepted on {host}:{port} (no banner)"
                ev = Evidence("tcp", f"TCP/{port} accepted a connection", capture, request=f"CONNECT {host}:{port}")
                add(protocol_type, ev)
                signals["banner"] = capture
            except OSError:
                pass

        if parsed.scheme == "https":
            try:
                cert = await asyncio.to_thread(self._certificate, host, port)
                signals["tls_certificate_sha256"] = cert
                add(AssetType.WEB_SERVER, Evidence("tls", "TLS certificate captured", f"DER SHA-256: {cert}", request=f"TLS {host}:{port}"))
            except OSError:
                pass

        if not classifications:
            add(AssetType.UNKNOWN, Evidence("target", "No reachable protocol identified", target, strength="weak"))
        profile = AssetProfile(target, normalized, [
            AssetClassification(kind, self._class_confidence(evs), evs)
            for kind, evs in sorted(classifications.items(), key=lambda pair: pair[0].value)
        ], signals)
        network_worked = bool(signals.get("addresses") or signals.get("http") or signals.get("banner"))
        return profile, Mode.ONLINE if network_worked else Mode.OFFLINE_STATIC

    @staticmethod
    def _normalize(target: str) -> tuple[str, str, int | None]:
        value = target if "://" in target else f"http://{target}"
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError(f"invalid target: {target}")
        return value, parsed.hostname, parsed.port

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
            return True
        except OSError:
            return False

    def _certificate(self, host: str, port: int) -> str:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()

    @staticmethod
    def _class_confidence(evidence: list[Evidence]) -> str:
        return "High" if any(item.kind in {"http-signature", "http", "tls"} for item in evidence) else "Medium"

    @staticmethod
    def _file_profile(path: Path) -> AssetProfile:
        if path.is_dir():
            is_repo = (path / ".git").exists()
            kind = AssetType.GIT if is_repo else AssetType.UNKNOWN
            names = sorted(item.name for item in path.iterdir())[:100]
            ev = Evidence("directory", "Local directory inspected", f"path={path}; entries={names}", request="local directory read")
            return AssetProfile(str(path), str(path.resolve()), [AssetClassification(kind, "High" if is_repo else "Low", [ev])], {"directory_entries": names})
        data = path.read_bytes()[:65536]
        suffix = path.suffix.lower()
        types = [AssetType.JAVASCRIPT] if suffix in {".js", ".mjs"} else [AssetType.UNKNOWN]
        if suffix == ".map":
            types = [AssetType.SOURCE_MAP]
        if path.name == ".git" or suffix in {".git", ".patch"}:
            types = [AssetType.GIT]
        magic = data[:16].hex()
        ev = Evidence("file", "Local file inspected", f"path={path}; magic={magic}; size={path.stat().st_size}", request="local read")
        return AssetProfile(str(path), str(path.resolve()), [AssetClassification(kind, "High", [ev]) for kind in types], {"file_bytes": data.decode("utf-8", "replace")})
