# CYGNUS Hardcoded-Output Audit

Audit date: 2026-07-11

Original repository baseline: `ca6cca8f56a9dd06efea1ec02cdd8b200cf69498`

## Baseline result

The original linked baseline contains only `README.md` with the single line `# BUGFINDER`. It does not contain the operator-described legacy scanner, Agoda/LaunchDarkly report generator, 96-item finding array, or fixed `23 Critical / 25 High / 32 Medium / 16 Low` breakdown. Those absent file locations cannot be truthfully invented. If that implementation exists in another service, package, or unmerged branch, it must be supplied for a line-level audit.

```text
git ls-tree -r --name-only ca6cca8f56a9dd06efea1ec02cdd8b200cf69498
README.md

git show ca6cca8f56a9dd06efea1ec02cdd8b200cf69498:README.md
# BUGFINDER
```

## Current-tree fixed-output audit

Searches for the reported fixed counts, 96-item output, large finding literals, and repeated candidate names found no static finding collection. Finding constructors occur only inside check-specific positive branches. Local CVE JSON is knowledge-base input, not output: a finding requires an exact captured product/version signal and remains manual verification when evidence is only moderate.

The only fixed lists affecting output are safety/policy data:

- `CHAIN_RULES`: explicit dependency sets; all required tags must belong to confirmed findings.
- Module `applies_to` sets: asset relevance routing.
- Bounded protocol signatures and secret patterns: detection conditions, never unconditional findings.
- Locally cited NVD-derived CVE records: exact-match inputs, never emitted globally.

## Replacement verification map

| Asset family | Actual evidence required | No positive evidence |
|---|---|---|
| Web/API | Fresh HTTP response, headers, synthetic CORS origin behavior, benign reflection marker, or explicit identifier/interface signal | Empty candidate list |
| FTP/SSH/network | Fresh TCP banner/feature response and optional exact cached version match | Empty candidate list |
| Kubernetes/Docker | Fresh unauthenticated identity endpoint response with platform signature | Empty candidate list |
| Cloud/storage | Fresh unauthenticated listing structure | Empty candidate list |
| CMS/CRM/ERP | Fresh product/version response plus exact NVD-cache correlation | Empty candidate list |
| Git/CI/package | Fresh interface response or operator-provided file content with redacted match | Empty candidate list |
| IoT/network device | Fresh management banner indicator; no credential submission | Empty candidate list |

## Final invariants

`ScanEngine` now performs a final fail-closed pass after scoring. A finding is excluded from confirmed/manual counts and chains if evidence is empty, `observed_at` is invalid or lacks a timezone, status is invalid, or its asset type is absent from the fingerprinted `AssetProfile`. Applicable modules execute as independent async coroutines and module errors remain isolated in `ModuleResult`.

Regression fixtures cover distinct web, FTP, Kubernetes, and repository targets with secure negative controls. A dedicated test fails when distinct vulnerable/secure targets collapse to the same count/severity signature.
