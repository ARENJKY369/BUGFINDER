from collections import Counter

import pytest

from cygnus.core.engine import ScanEngine
from cygnus.core.models import AssetType, ScanContext
from cygnus.fingerprint.engine import Fingerprinter
from cygnus.report.writer import to_json


async def scan(target):
    profile, mode = await Fingerprinter(timeout=1).run(target)
    report = await ScanEngine().run(profile, ScanContext(mode, "TEST-AUTH", timeout=1))
    return profile, report


@pytest.mark.asyncio
async def test_web_fingerprint_relevance_and_vulnerability_toggle(http_target):
    insecure = {"body": '<html><form action="/login"></form></html>', "cors": True, "reflect": True}
    secure = {
        "body": "<html><body>static documentation</body></html>",
        "headers": {"Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"},
    }
    with http_target(insecure) as target:
        profile_bad, report_bad = await scan(target)
    with http_target(secure) as target:
        profile_good, report_good = await scan(target)

    assert AssetType.WEB_APPLICATION in profile_bad.types
    assert any(item.module == "web.cors" and item.status == "ran" for item in report_bad.module_results)
    assert all(item.status == "skipped" for item in report_bad.module_results if item.module.startswith("network."))
    assert {item.name for item in report_bad.confirmed} >= {"Missing browser security headers", "Untrusted cross-origin access allowed"}
    assert not report_good.confirmed
    assert to_json(report_bad) != to_json(report_good)


@pytest.mark.asyncio
async def test_ftp_fingerprint_only_network_module_and_toggle(ftp_target):
    with ftp_target(True) as target:
        profile_open, report_open = await scan(target)
    with ftp_target(False) as target:
        profile_closed, report_closed = await scan(target)

    assert AssetType.FTP in profile_open.types
    assert any(result.module == "network.banner_configuration" and result.status == "ran" for result in report_open.module_results)
    assert all(result.status == "skipped" for result in report_open.module_results if result.module.startswith("web."))
    assert any("anonymous" in finding.name.lower() for finding in report_open.confirmed)
    assert not any("anonymous" in finding.name.lower() for finding in report_closed.confirmed + report_closed.manual)


@pytest.mark.asyncio
async def test_exposed_dashboard_detected_and_disappears(http_target):
    with http_target({"body": "<html>Kubernetes Dashboard</html>", "dashboard": True}) as target:
        profile_exposed, report_exposed = await scan(target)
    with http_target({"body": "<html>ordinary landing page</html>"}) as target:
        profile_plain, report_plain = await scan(target)

    assert AssetType.KUBERNETES in profile_exposed.types
    container_result = next(item for item in report_exposed.module_results if item.module == "containers.exposed_control_plane")
    assert container_result.status == "ran"
    assert any("control-plane" in finding.name for finding in report_exposed.confirmed)
    plain_result = next(item for item in report_plain.module_results if item.module == "containers.exposed_control_plane")
    assert plain_result.status == "skipped"
    assert not any("control-plane" in finding.name for finding in report_plain.confirmed)


@pytest.mark.asyncio
async def test_operator_repository_secret_is_static_unconfirmed(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "settings.env").write_text("AWS_KEY=AKIAABCDEFGHIJKLMNOP\n")
    profile, mode = await Fingerprinter(timeout=1).run(str(repo))
    report = await ScanEngine().run(profile, ScanContext(mode, "TEST-AUTH", timeout=1, repository_path=str(repo)))

    assert AssetType.GIT in profile.types
    assert not report.confirmed
    assert len(report.manual) == 1
    assert report.manual[0].status == "STATIC/UNCONFIRMED"
    assert "ABCDEFGHIJKLMNOP" not in report.manual[0].evidence[0].captured


@pytest.mark.asyncio
async def test_regression_distinct_targets_do_not_share_static_breakdown(http_target):
    with http_target({"body": "<html><form></form></html>", "cors": True}) as first:
        _, a = await scan(first)
    with http_target({"body": "<html>secure</html>", "headers": {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"}}) as second:
        _, b = await scan(second)

    signature_a = (len(a.confirmed), Counter(f.severity for f in a.confirmed))
    signature_b = (len(b.confirmed), Counter(f.severity for f in b.confirmed))
    assert signature_a != signature_b, "regression: distinct vulnerable/secure targets produced the same static finding breakdown"
