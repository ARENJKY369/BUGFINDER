"""Plugin contract and discovery. Adding modules requires no engine edits."""
from __future__ import annotations

import importlib
import pkgutil
from typing import Protocol

from .models import AssetProfile, AssetType, FindingCandidate, ScanContext


class CheckModule(Protocol):
    name: str
    applies_to: frozenset[AssetType]
    requires_active: bool

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]: ...


def discover_modules() -> list[CheckModule]:
    import cygnus.modules as package

    discovered: list[CheckModule] = []
    for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if not info.name.endswith(".checks"):
            continue
        module = importlib.import_module(info.name)
        discovered.extend(getattr(module, "MODULES", []))
    return sorted(discovered, key=lambda item: item.name)
