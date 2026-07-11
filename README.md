<p align="center"><img src="cygnus/assets/cygnus-logo.svg" width="150" alt="CYGNUS logo"></p>
<h1 align="center">CYGNUS</h1>
<p align="center"><strong>Evidence-Based · Verification-Driven Bug Bounty Automation</strong></p>

> **Authorization comes first.** CYGNUS will not touch a target until the operator explicitly confirms permission, supplies an authorization reference, and the target matches a required allowlist. Use it only on assets you own, an in-scope bounty target, or systems for which you have written permission.

CYGNUS is an asset-aware security verification CLI. It fingerprints what actually answers, dynamically selects only relevant check plugins, discards candidates without captured evidence, computes confidence/severity centrally, and produces a traceable report. It does **not** emit a universal finding template or claim that a harmless reflection/version string is a confirmed exploit.

## Safety model

- Passive/detection-only by default. No guessed logins, uploads, writes, or exploit payloads.
- `--active` requires a distinct `--active-authorized` confirmation. The current built-in set remains detection-only; the gate exists for separately reviewed future active plugins.
- Every attempt—allowed or denied—is appended to `.cygnus/audit.jsonl` by default.
- `ONLINE` is selected only from runtime DNS/protocol reachability. Local files/directories and unreachable targets become `OFFLINE-STATIC`.
- Offline findings are tagged `STATIC/UNCONFIRMED` and excluded from confirmed severity totals.
- Captures are truncated and secret-pattern matches are redacted. Reports can still contain sensitive banners/content; handle them accordingly.

## Architecture

```text
operator / CLI
      │
      ▼
┌──────────────────────────────┐
│ authorization + scope + audit│  hard gate; runs before network access
└──────────────┬───────────────┘
               ▼
┌──────────┐  AssetProfile   ┌─────────────────────────────────────┐
│fingerprint├───────────────►│ plugin discovery + applicability gate│
│DNS/TCP/  │                 └──────────────┬──────────────────────┘
│TLS/HTTP/ │                                ▼
│file magic│                 ┌─────────────────────────────────────┐
└──────────┘                 │ web · network · cloud · containers  │
                             │ enterprise · supply-chain · IoT     │
                             └──────────────┬──────────────────────┘
                                            ▼
                             ┌─────────────────────────────────────┐
                             │ evidence validator + central scoring│
                             │ explicit chain dependency rules     │
                             └──────────────┬──────────────────────┘
                                            ▼
                                      Markdown / JSON report
```

A plugin is a class in `cygnus/modules/<category>/checks.py` exposing `name`, `applies_to`, `requires_active`, and async `run(profile, context)`. Discovery is automatic; adding a folder does not change the engine or report schema.

## Install

Python 3.11 or newer is required.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

## Scope and usage

One allowlist item per line; blank lines and `#` comments are ignored. Exact domains, wildcard subdomains, IP addresses, CIDRs, and local paths are accepted.

```text
# scope.txt
example.com
*.staging.example.com
192.0.2.0/24
/home/operator/authorized-repo
```

Non-interactive passive scan:

```bash
cygnus https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'H1-PROGRAM-2026' \
  --output report.md
```

Interactive terminals may omit `--authorized` and the reference; CYGNUS prints its banner and asks at the gate. CI should pass explicit flags. JSON output is available with `--format json`. An operator-provided repository can be inspected without network access:

```bash
cygnus /home/operator/authorized-repo --scope scope.txt --authorized \
  --authorization-ref INTERNAL-42 --repository-path /home/operator/authorized-repo
```

The second active gate is deliberately separate:

```bash
cygnus https://example.com --scope scope.txt --authorized --authorization-ref TICKET-1 \
  --active --active-authorized --active-authorization-ref TICKET-1-ACTIVE
```

## Implemented verification categories

- **Web/API:** browser headers, untrusted-origin CORS, harmless reflected marker, public admin/API-documentation indicator.
- **SSH/FTP/RDP/email/network:** protocol banner/config capture and exact product/version correlation against the local NVD-derived cache. FTP anonymous access is detected only when advertised; no login is submitted.
- **Cloud/storage:** unauthenticated object-list response detection. Authenticated policy checks use only future operator-provided credentials; CYGNUS never discovers credentials itself.
- **Kubernetes/Docker:** unauthenticated identity endpoint detection (`/version`, `/_ping`) only; no control-plane operation.
- **CMS/CRM/ERP:** published exact product/version match against the cache, routed to manual verification because backports can invalidate banner-only conclusions.
- **Git/CI/CD/package registries:** public interface classification plus redacted secret patterns in an explicitly operator-provided local repository.
- **IoT/network devices:** default-credential *indicators* only. No credentials are attempted.

The local cache at `cygnus/data/cve_cache.json` identifies its NIST NVD API source, per-CVE NVD links, and last-updated date. It is intentionally small, so a cache miss means “not matched,” never “not vulnerable.”

## Report semantics

Confirmed counts contain only live, evidence-backed results that pass confidence rules. Weak indicators, harmless reflection, public-interface exposure, and version/CVE correlations are shown under **Needs Manual Verification**. Exploit chains are emitted only when every tag in a predefined dependency rule belongs to a confirmed finding.

## Tests

The integration suite starts local vulnerable and secure HTTP, FTP, and Kubernetes-dashboard mocks. It asserts classification, explicit plugin skips, finding disappearance after secure reconfiguration, report differences, and a regression signature preventing the historical static-output failure.
