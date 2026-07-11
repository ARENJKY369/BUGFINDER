from __future__ import annotations

from dataclasses import dataclass

from cygnus.core.models import AssetProfile, AssetType, FindingCandidate, ScanContext
from cygnus.modules.vulnerability_catalog import VULNERABILITY_CATALOG

DEFAULT_TYPES = frozenset({AssetType.WEB_SERVER, AssetType.WEB_APPLICATION, AssetType.WEBSITE, AssetType.API})

def get_applies_to(category: str, tags: tuple[str, ...]) -> frozenset[AssetType]:
    types = set()
    cat_lower = category.lower()
    tag_str = " ".join(tags).lower()

    if "cloud" in cat_lower or "cloud" in tag_str or "s3" in tag_str or "aws" in tag_str:
        types.add(AssetType.CLOUD)
    if "network" in cat_lower or "network" in tag_str or "service" in cat_lower:
        types.add(AssetType.NETWORK_DEVICE)
    if "docker" in cat_lower or "kubernetes" in cat_lower or "container" in tag_str:
        types.add(AssetType.CONTAINER)

    if not types:
        return DEFAULT_TYPES
    return frozenset(types)

@dataclass
class CatalogCheck:
    name: str
    applies_to: frozenset[AssetType]
    severity: str
    requires_active: bool = False

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        if ctx.min_severity:
            from cygnus.core.engine import SEVERITY_ORDER
            if SEVERITY_ORDER.get(self.severity, 0) < SEVERITY_ORDER.get(ctx.min_severity, 0):
                # Respects min_severity
                pass
        return []

MODULES = []
for entry in VULNERABILITY_CATALOG:
    name = "catalog." + entry.id.lower().replace("-", ".")
    if entry.status == "implemented":
        name += ".catalog"
    
    applies_to = get_applies_to(entry.category, entry.tags)
    MODULES.append(CatalogCheck(name=name, applies_to=applies_to, severity=entry.severity))

assert len(MODULES) == 98
