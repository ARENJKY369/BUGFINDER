<p align="center"><img src="cygnus/assets/cygnus-logo.png" width="220" alt="CYGNUS swan shield logo"></p>
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

## Installation

CYGNUS requires **Python 3.11 or newer**. First, clone or download the repository and enter the project directory.

```bash
git clone https://github.com/ARENJKY369/BUGFINDER.git
cd BUGFINDER
```

### Linux / macOS

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the project and test dependencies from `requirements.txt`:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The requirements file installs CYGNUS in editable mode together with the test dependencies declared by the project.

Verify the installation:

```bash
python -m cygnus.cli.main --help
pytest
```

`python -m pip install -r requirements.txt` installs CYGNUS in editable mode and makes the `cygnus` terminal command available. When returning to the project, you do not need to reinstall the dependencies; simply reactivate `.venv`.

## Authorization and scope setup

> Run CYGNUS only against an asset you own, an in-scope bug-bounty target, or a target for which you have written permission. Every scan requires an authorization reference and a scope allowlist.

Create `scope.txt` in the project directory and place one authorized asset on each line. Blank lines and `#` comments are ignored. Exact domains, wildcard subdomains, IP addresses, CIDRs, and local repository paths are supported.

```text
# scope.txt
example.com
*.staging.example.com
192.0.2.0/24
/home/operator/authorized-repo
```

The target host must match an entry in the scope file. For example, scanning `https://api.example.com` requires either `api.example.com` or a matching wildcard entry in scope.

## What is an authorization reference?

An authorization reference is **your record of permission**, not a value supplied by CYGNUS or its developers. It helps identify why you are allowed to scan the target. Examples include:

- A bug-bounty program name or public program URL
- An internal security ticket such as `SEC-1234`
- A penetration-test statement-of-work identifier
- A written approval or change-request identifier

Do not place passwords, API keys, access tokens, or other secrets in this field.

You may omit the authorization flags from an interactive command. CYGNUS will then ask whether you have permission and prompt for the reference before making network requests. The reference itself cannot be bypassed because it is part of the mandatory audit trail.

## Basic interactive usage

The simplest command requires only the target and scope file:

```bash
python -m cygnus.cli.main TARGET --scope scope.txt
```

CYGNUS will display prompts similar to:

```text
Authorization gate: do you have explicit permission for TARGET? Type 'yes': yes
Authorization/scope reference: SEC-1234
```

The package also installs a shorter `cygnus` command, but all examples below use `python -m cygnus.cli.main` so the invocation is explicit and easy to troubleshoot.

## Usage examples

### Full asset-aware passive scan

CYGNUS fingerprints the target first, then runs only the modules applicable to the detected asset types. Manual `-m` module selection is not required.

```bash
python -m cygnus.cli.main https://example.com --scope scope.txt
```

### API target scan

After adding the API to the scope file, pass it as a normal target. REST, GraphQL, API-documentation, authentication, and web checks are automatically selected or skipped according to fingerprint evidence.

```bash
python -m cygnus.cli.main https://api.example.com \
  --scope scope.txt \
  --output api-report.md
```

### Domain or reconnaissance-oriented passive scan

The current CLI does not have a separate `-m recon` switch. The default scan is already passive and detection-only, and begins with DNS, TCP/banner, TLS, HTTP, and asset fingerprinting.

```bash
python -m cygnus.cli.main example.com \
  --scope scope.txt \
  --timeout 5
```

### Save a Markdown report

Markdown is the default report format:

```bash
python -m cygnus.cli.main https://example.com \
  --scope scope.txt \
  --format markdown \
  --output report.md
```

### Save a JSON report

```bash
python -m cygnus.cli.main https://example.com \
  --scope scope.txt \
  --format json \
  --output report.json
```

The current version supports Markdown and JSON. `--format html` and `--depth aggressive` are not implemented options, so this README does not advertise them as supported commands.

### Offline/local repository scan

Add the authorized local repository path to `scope.txt`, then pass the same path as both the target and `--repository-path`:

```bash
python -m cygnus.cli.main /home/operator/authorized-repo \
  --scope scope.txt \
  --repository-path /home/operator/authorized-repo \
  --output repository-report.md
```

Local source findings appear in the `STATIC/UNCONFIRMED` section and are excluded from confirmed severity totals. The interactive authorization prompt still appears for local scans.

### Non-interactive or CI usage

CI cannot answer interactive prompts, so it must provide the confirmation and reference explicitly:

```bash
python -m cygnus.cli.main https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'SEC-1234' \
  --format json \
  --output report.json
```

Replace `SEC-1234` with your real program, ticket, or written-approval reference.

### Explicit active-mode authorization

Checks are passive by default. Enabling active modules requires a separate active confirmation in addition to normal authorization. In an interactive terminal, use:

```bash
python -m cygnus.cli.main https://example.com \
  --scope scope.txt \
  --active
```

CYGNUS asks for the normal authorization reference and a second `ACTIVE-AUTHORIZED` confirmation. For non-interactive automation, all active authorization flags must be explicit:

```bash
python -m cygnus.cli.main https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'SEC-1234' \
  --active \
  --active-authorized \
  --active-authorization-ref 'SEC-1234-ACTIVE'
```

The scan is blocked if the normal authorization/reference or separate active confirmation is missing.

### View supported options and asset types

```bash
python -m cygnus.cli.main --help
```

The current CLI does not provide a `--list-assets` option. Supported asset types are defined by the `AssetType` enum in `cygnus/core/models.py`, and detection is automatic—the operator does not manually force an asset type.

## Important command differences

The following example flags are **not** part of the current CYGNUS CLI:

```text
-m api
-m recon
--depth aggressive
--format html
--list-assets
```

Their current equivalents are:

- **API scan:** Pass the API URL as a normal target; modules are selected automatically.
- **Recon:** The default passive scan begins with fingerprinting.
- **Aggressive mode:** This is intentionally unavailable; gated active checks use `--active` plus a second confirmation.
- **HTML report:** Generate Markdown or JSON and use a trusted external renderer.
- **Asset list:** Review the `AssetType` enum; types detected at runtime are shown in the report header.

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

## Finding output invariants

Each finding includes a stable evidence ID, detected asset type, computed severity/confidence, timezone-aware UTC `observed_at`, exact component, captured evidence, root cause, exploitation vector, remediation, status, and optional locally cited CVE metadata. A final fail-closed pass removes findings with empty evidence, invalid timestamps/status, or asset tags not present in the fingerprint profile before severity totals or exploit chains are generated.

Applicable check plugins are independent async functions and execute concurrently. Inapplicable plugins remain explicit `skipped` ledger entries; protocol failures are isolated as `error` entries rather than converted into findings.

See [`AUDIT_REPORT.md`](AUDIT_REPORT.md) for the hardcoded-output audit and the live verification replacement map.
