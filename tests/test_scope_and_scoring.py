import json
from pathlib import Path

import pytest

from cygnus.core.models import AssetType, Evidence, FindingCandidate, Mode
from cygnus.core.scope import AuthorizationError, Scope, require_authorization
from cygnus.core.engine import ScanEngine


def test_scope_domains_ips_and_cidr(tmp_path):
    scope = Scope(["example.com", "*.allowed.test", "127.0.0.0/8"])
    assert scope.permits("https://example.com/path")
    assert scope.permits("api.allowed.test")
    assert scope.permits("127.0.0.1:8080")
    assert not scope.permits("evil-example.com")


def test_authorization_and_second_active_gate():
    with pytest.raises(AuthorizationError):
        require_authorization(False, None, False, False)
    with pytest.raises(AuthorizationError):
        require_authorization(True, "TICKET-1", True, False)
    assert require_authorization(True, "TICKET-1", True, True) == "TICKET-1"


def test_cve_cache_has_source_and_date():
    data = json.loads((Path(__file__).parents[1] / "cygnus/data/cve_cache.json").read_text())
    assert data["metadata"]["source"].startswith("NIST National Vulnerability Database")
    assert data["metadata"]["last_updated"]
    assert all(entry["source"].startswith("https://nvd.nist.gov/vuln/detail/CVE-") for entry in data["entries"])
