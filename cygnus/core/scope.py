"""Authorization and scope controls. No network operation belongs in this module."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse


class AuthorizationError(RuntimeError):
    pass


class Scope:
    def __init__(self, entries: list[str]):
        self.entries = [line.strip().lower() for line in entries if line.strip() and not line.lstrip().startswith("#")]
        if not self.entries:
            raise AuthorizationError("scope allowlist is empty")

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        return cls(Path(path).read_text(encoding="utf-8").splitlines())

    @staticmethod
    def target_host(target: str) -> str:
        parsed = urlparse(target if "://" in target else f"//{target}")
        return (parsed.hostname or target.split(":", 1)[0]).rstrip(".").lower()

    def permits(self, target: str) -> bool:
        local = Path(target)
        if local.exists():
            resolved = str(local.resolve()).lower()
            return any(resolved == str(Path(entry).expanduser().resolve()).lower() or resolved.startswith(str(Path(entry).expanduser().resolve()).lower() + "/") for entry in self.entries)
        host = self.target_host(target)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        for entry in self.entries:
            clean = entry.removeprefix("*.").rstrip(".")
            try:
                if address is not None and address in ipaddress.ip_network(clean, strict=False):
                    return True
            except ValueError:
                pass
            if host == clean or (entry.startswith("*.") and host.endswith("." + clean)):
                return True
        return False


def require_authorization(confirmed: bool, reference: str | None, active: bool, active_confirmed: bool) -> str:
    if not confirmed or not reference or not reference.strip():
        raise AuthorizationError("explicit authorization and a non-empty authorization reference are required")
    if active and not active_confirmed:
        raise AuthorizationError("--active requires a second, separate active authorization confirmation")
    return reference.strip()
