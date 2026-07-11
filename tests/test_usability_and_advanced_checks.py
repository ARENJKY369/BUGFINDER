from __future__ import annotations
import subprocess,sys
from datetime import datetime

import pytest

from cygnus.cli.main import _resolve_target,_utility,parser
from cygnus.core.engine import ScanEngine
from cygnus.core.models import AssetType,ScanContext
from cygnus.core.transport import HTTPExchange
from cygnus.fingerprint.engine import Fingerprinter


def test_target_option_and_positional_commands_remain_compatible():
    command=parser()
    positional=command.parse_args(["https://example.com","--scope","scope.txt"])
    _resolve_target(positional,command)
    optional=command.parse_args(["-t","https://example.com","--scope","scope.txt"])
    _resolve_target(optional,command)
    assert positional.target==optional.target=="https://example.com"


def test_init_scope_creates_safe_single_entry(tmp_path):
    output=tmp_path/"scope.txt"
    args=parser().parse_args(["-t","https://api.example.com/v1","--init-scope",str(output)])
    assert _utility(args)
    assert output.read_text().splitlines()[-1]=="api.example.com"


def test_python_module_entrypoint_lists_assets_without_scan():
    completed=subprocess.run([sys.executable,"-m","cygnus","--list-assets"],text=True,capture_output=True,check=True)
    assert "Web Applications" in completed.stdout
    assert "Kubernetes Clusters" in completed.stdout


def test_capture_redacts_session_material():
    exchange=HTTPExchange("https://example.test","GET",200,{"set-cookie":"session=secret","server":"mock"},b"ok")
    assert "session=secret" not in exchange.capture()
    assert "[REDACTED]" in exchange.capture()


@pytest.mark.asyncio
async def test_openid_discovery_selects_auth_module_and_evidence(http_target):
    metadata='{"issuer":"http://identity.local","id_token_signing_alg_values_supported":["RS256"]}'
    with http_target({"body":"<html>login</html>","openid":metadata}) as target:
        profile,mode=await Fingerprinter(1).run(target)
        report=await ScanEngine().run(profile,ScanContext(mode,"TEST",timeout=1))
    assert {AssetType.OAUTH_SSO,AssetType.IDENTITY_PROVIDER} <= profile.types
    assert any(result.module=="auth.openid_metadata_policy" and result.status=="ran" for result in report.module_results)
    finding=next(item for item in report.confirmed if item.name=="OpenID issuer uses insecure transport")
    assert datetime.fromisoformat(finding.observed_at).tzinfo is not None


@pytest.mark.asyncio
async def test_graphql_introspection_is_manual_not_confirmed(http_target):
    with http_target({"body":"<html>GraphQL endpoint</html>","graphql":True}) as target:
        profile,mode=await Fingerprinter(1).run(target)
        report=await ScanEngine().run(profile,ScanContext(mode,"TEST",timeout=1))
    assert AssetType.GRAPHQL in profile.types
    finding=next(item for item in report.manual if item.name.startswith("GraphQL schema introspection"))
    assert finding.severity in {"Low","Medium"} and finding.confidence=="Low"

@pytest.mark.asyncio
async def test_openapi_object_review_requires_explicit_empty_security(http_target):
    specification='{"openapi":"3.1.0","paths":{"/users/{id}":{"get":{"security":[]}}}}'
    with http_target({"body":"<html>API</html>","openapi":specification}) as target:
        profile,mode=await Fingerprinter(1).run(target)
        report=await ScanEngine().run(profile,ScanContext(mode,"TEST",timeout=1))
    assert AssetType.API_DOCS in profile.types
    finding=next(item for item in report.manual if item.name.startswith("Object-level authorization review"))
    assert "GET /users/{id}" in finding.evidence[0].captured
    assert not any("IDOR" in item.name for item in report.confirmed)
