import asyncio
from datetime import datetime

import pytest

from cygnus.core.engine import ScanEngine
from cygnus.core.models import (
    AssetClassification, AssetProfile, AssetType, Evidence, FindingCandidate,
    Mode, ScanContext,
)


def profile():
    evidence=Evidence("test","mock classification","HTTP 200")
    return AssetProfile("mock","http://mock",[AssetClassification(AssetType.WEBSITE,"High",[evidence])])


@pytest.mark.asyncio
async def test_applicable_modules_execute_concurrently():
    arrived=0
    ready=asyncio.Event()
    class BarrierModule:
        applies_to=frozenset({AssetType.WEBSITE}); requires_active=False
        def __init__(self,name):self.name=name
        async def run(self,target,ctx):
            nonlocal arrived
            arrived+=1
            if arrived==2:ready.set()
            await asyncio.wait_for(ready.wait(),0.5)
            return []
    report=await ScanEngine([BarrierModule("one"),BarrierModule("two")]).run(profile(),ScanContext(Mode.ONLINE,"TEST"))
    assert [result.status for result in report.module_results]==["ran","ran"]


@pytest.mark.asyncio
async def test_final_validation_discards_wrong_asset_tag():
    class WrongAssetModule:
        name="wrong-asset"; applies_to=frozenset({AssetType.WEBSITE}); requires_active=False
        async def run(self,target,ctx):
            return [FindingCandidate("wrong tag",AssetType.FTP,"mock",[Evidence("test","captured","220 FTP")],"cause","vector","fix")]
    report=await ScanEngine([WrongAssetModule()]).run(profile(),ScanContext(Mode.ONLINE,"TEST"))
    assert not report.confirmed and not report.manual
    assert report.discarded_findings and "absent from fingerprint profile" in report.discarded_findings[0]


@pytest.mark.asyncio
async def test_findings_have_real_timezone_timestamp(http_target):
    from cygnus.fingerprint.engine import Fingerprinter
    with http_target({"body":"<html><form></form></html>"}) as target:
        detected,mode=await Fingerprinter(timeout=1).run(target)
        report=await ScanEngine().run(detected,ScanContext(mode,"TEST",timeout=1))
    findings=report.confirmed+report.manual
    assert findings
    assert all(datetime.fromisoformat(item.observed_at).tzinfo is not None for item in findings)
    assert all(item.asset_type in detected.types for item in findings)
