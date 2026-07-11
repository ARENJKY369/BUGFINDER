"""Stable data contracts shared by fingerprint, plugins, and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Mode(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE_STATIC = "OFFLINE-STATIC"


class AssetType(str, Enum):
    WEB_APPLICATION = "Web Applications"
    WEBSITE = "Websites"
    API = "APIs"
    GRAPHQL = "GraphQL Endpoints"
    JAVASCRIPT = "JavaScript Files"
    SOURCE_MAP = "Source Maps"
    AUTH = "Authentication Systems"
    ADMIN_PANEL = "Admin Panels"
    DOMAIN = "Domains"
    SUBDOMAIN = "Subdomains"
    IP_ADDRESS = "IP Addresses"
    WEB_SERVER = "Web Servers"
    SSH = "SSH Services"
    FTP = "FTP/SFTP Servers"
    RDP = "Remote Desktop Services"
    VPN = "VPN Gateways"
    DNS = "DNS Servers"
    EMAIL = "Email Servers"
    DATABASE = "Databases"
    CLOUD = "Cloud Assets"
    OBJECT_STORAGE = "Object Storage Buckets"
    KUBERNETES = "Kubernetes Clusters"
    DOCKER = "Docker Services"
    CONTAINER = "Containers"
    CMS = "CMS Platforms"
    CRM = "CRM Systems"
    ERP = "ERP Systems"
    GIT = "Public Git Repositories"
    CICD = "CI/CD Pipelines"
    PACKAGE_REGISTRY = "Package Registries"
    IOT = "IoT Devices"
    NETWORK_DEVICE = "Network Devices"
    API_DOCS = "API Documentation"
    DEVELOPER_PORTAL = "Developer Portals"
    WEBSOCKET = "WebSockets"
    GRPC = "gRPC Services"
    MOBILE_ANDROID = "Mobile Applications (Android)"
    MOBILE_IOS = "Mobile Applications (iOS)"
    DESKTOP = "Desktop Applications"
    APPLICATION_SERVER = "Application Servers"
    SERVERLESS = "Serverless Functions"
    VIRTUAL_MACHINE = "Virtual Machines"
    LOAD_BALANCER = "Load Balancers"
    REVERSE_PROXY = "Reverse Proxies"
    OAUTH_SSO = "OAuth/SSO"
    IDENTITY_PROVIDER = "Identity Providers"
    USER_DASHBOARD = "User Dashboards"
    FILE_UPLOAD = "File Upload Endpoints"
    FILE_DOWNLOAD = "File Download Endpoints"
    SEARCH = "Search Functionality"
    PAYMENT = "Payment Systems"
    CHAT = "Chat Systems"
    NOTIFICATION = "Notification Systems"
    SERVICE_WORKER = "Service Workers"
    BROWSER_EXTENSION = "Browser Extensions"
    EMBEDDED = "Embedded Systems"
    FIREWALL = "Firewalls"
    WAF = "WAFs"
    ROUTER = "Routers"
    SWITCH = "Switches"
    WIRELESS = "Wireless Networks"
    THIRD_PARTY = "Third-Party Integrations"
    ARTIFACT_REPOSITORY = "Artifact Repositories"
    MICROSERVICE = "Microservices"
    MESSAGE_QUEUE = "Message Queues"
    CACHE_SERVER = "Caching Servers"
    MONITORING = "Monitoring Dashboards"
    LOGGING = "Logging Systems"
    WEBHOOK = "Webhooks"
    WEBRTC = "WebRTC Applications"
    CDN = "CDN Endpoints"
    FTP_SERVER = "FTP Servers"
    SFTP = "SFTP Servers"
    UNKNOWN = "Unknown"


@dataclass(slots=True)
class Evidence:
    kind: str
    summary: str
    captured: str
    request: str | None = None
    source: str | None = None
    strength: str = "strong"  # strong, moderate, weak

    def __post_init__(self) -> None:
        self.captured = self.captured[:4096]
        if not self.captured.strip():
            raise ValueError("evidence capture cannot be empty")


@dataclass(slots=True)
class AssetClassification:
    type: AssetType
    confidence: str
    evidence: list[Evidence]


@dataclass(slots=True)
class AssetProfile:
    target: str
    normalized_target: str
    classifications: list[AssetClassification]
    signals: dict[str, Any] = field(default_factory=dict)

    @property
    def types(self) -> set[AssetType]:
        return {item.type for item in self.classifications}


@dataclass(slots=True)
class FindingCandidate:
    name: str
    asset_type: AssetType
    component: str
    evidence: list[Evidence]
    root_cause: str
    exploitation_vector: str
    remediation: str
    impact: str = "limited"
    cve: dict[str, str] | None = None
    tags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class Finding:
    id: str
    name: str
    asset_type: AssetType
    severity: str
    confidence: str
    status: str
    observed_at: str
    component: str
    evidence: list[Evidence]
    root_cause: str
    exploitation_vector: str
    remediation: str
    cve: dict[str, str] | None = None
    tags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ModuleResult:
    module: str
    status: str  # ran, skipped, error
    reason: str
    findings: list[FindingCandidate] = field(default_factory=list)


@dataclass(slots=True)
class ScanContext:
    mode: Mode
    authorization_reference: str
    active: bool = False
    active_authorization_reference: str | None = None
    timeout: float = 3.0
    credentials: dict[str, str] = field(default_factory=dict)
    repository_path: str | None = None


@dataclass(slots=True)
class ScanReport:
    mode: Mode
    profile: AssetProfile
    authorization_reference: str
    module_results: list[ModuleResult]
    confirmed: list[Finding]
    manual: list[Finding]
    chains: list[dict[str, Any]]
    next_steps: list[str]
    discarded_findings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, set):
                return sorted(value)
            if hasattr(value, "__dataclass_fields__"):
                return {k: convert(v) for k, v in asdict(value).items()}
            if isinstance(value, list):
                return [convert(v) for v in value]
            if isinstance(value, dict):
                return {k: convert(v) for k, v in value.items()}
            return value
        return convert(self)
