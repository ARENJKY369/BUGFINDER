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

CYGNUS ke liye **Python 3.11 ya newer** required hai. Pehle repository clone/download karke project directory mein enter karein.

```bash
git clone https://github.com/ARENJKY369/BUGFINDER.git
cd BUGFINDER
```

### Linux / macOS

Virtual environment create aur activate karein:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

Project aur test dependencies install karein:

```bash
python -m pip install --upgrade pip
pip install -e '.[test]'
```

Installation verify karne ke liye:

```bash
cygnus --help
pytest
```

`pip install -e '.[test]'` CYGNUS ko editable mode mein install karta hai aur `cygnus` terminal command available banata hai. Virtual environment dobara use karte waqt dependencies reinstall karne ki zarurat nahi hai—sirf `.venv` activate karein.

## Authorization aur scope setup

> CYGNUS ko sirf owned asset, in-scope bug-bounty target, ya written permission wale target par run karein. Har scan ke liye authorization reference aur scope allowlist required hai.

Project directory mein `scope.txt` banayein. Har line par ek authorized asset likhein. Blank lines aur `#` comments ignore hote hain. Exact domains, wildcard subdomains, IP addresses, CIDRs, aur local repository paths supported hain.

```text
# scope.txt
example.com
*.staging.example.com
192.0.2.0/24
/home/operator/authorized-repo
```

Target ka host scope file se match hona chahiye. Example: `https://api.example.com` scan karna hai to `api.example.com` ya applicable wildcard scope mein hona chahiye.

## Basic command structure

```bash
cygnus TARGET \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'YOUR-PERMISSION-REFERENCE'
```

Same CLI ko Python module ke through bhi run kar sakte hain:

```bash
python -m cygnus.cli.main TARGET \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'YOUR-PERMISSION-REFERENCE'
```

Installed `cygnus` command recommended aur shorter form hai.

## Usage examples

### Full asset-aware passive scan

CYGNUS pehle target fingerprint karta hai, phir sirf detected asset types ke applicable modules run karta hai. Manual `-m` module selection required nahi hai.

```bash
cygnus https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'H1-PROGRAM-2026'
```

### API target scan

API ko scope file mein allowlist karne ke baad normal target ki tarah pass karein. REST, GraphQL, API-documentation, authentication, aur web checks fingerprint evidence ke basis par automatically select ya skip honge.

```bash
cygnus https://api.example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'H1-API-SCOPE-2026' \
  --output api-report.md
```

### Domain or reconnaissance-oriented passive scan

Current CLI mein separate `-m recon` switch nahi hai. Default scan already passive/detection-only hai aur DNS, TCP/banner, TLS, HTTP, aur asset fingerprinting se start hota hai.

```bash
cygnus example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'RECON-AUTH-2026' \
  --timeout 5
```

### Markdown report save karna

Markdown default report format hai:

```bash
cygnus https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'TICKET-1001' \
  --format markdown \
  --output report.md
```

### JSON report save karna

```bash
cygnus https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'TICKET-1001' \
  --format json \
  --output report.json
```

Current version Markdown aur JSON support karta hai. `--format html` aur `--depth aggressive` abhi implemented options nahi hain; README intentionally unsupported commands advertise nahi karta.

### Offline/local repository scan

Authorized local repository path ko `scope.txt` mein bhi add karein, phir target aur `--repository-path` dono mein wahi path pass karein:

```bash
cygnus /home/operator/authorized-repo \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'INTERNAL-42' \
  --repository-path /home/operator/authorized-repo \
  --output repository-report.md
```

Local source findings `STATIC/UNCONFIRMED` section mein jaate hain aur confirmed severity totals mein count nahi hote.

### Explicit active-mode authorization

Default checks passive hain. Active modules enable karne ke liye normal authorization ke alawa separate active confirmation required hai:

```bash
cygnus https://example.com \
  --scope scope.txt \
  --authorized \
  --authorization-ref 'TICKET-1' \
  --active \
  --active-authorized \
  --active-authorization-ref 'TICKET-1-ACTIVE'
```

`--active` ko `--active-authorized` ke bina pass karne par scan block ho jayega.

### Interactive authorization

Interactive terminal mein `--authorized` aur `--authorization-ref` omit kar sakte hain:

```bash
cygnus https://example.com --scope scope.txt
```

CYGNUS banner print karke authorization gate par confirmation aur scope reference poochega. CI/CD ya non-interactive environment mein explicit flags use karein.

### Supported options aur asset types dekhna

```bash
cygnus --help
```

Current CLI mein `--list-assets` option nahi hai. Supported asset types `cygnus/core/models.py` ke `AssetType` enum mein defined hain, aur detection automatically hoti hai—asset type ko operator manually force nahi karta.

## Important command differences

Neeche wale example flags current CYGNUS CLI ka part **nahi** hain:

```text
-m api
-m recon
--depth aggressive
--format html
--list-assets
```

Inke current equivalents hain:

- **API scan:** API URL ko normal target ke roop mein pass karein; modules auto-select honge.
- **Recon:** default passive scan fingerprinting se start hota hai.
- **Aggressive mode:** intentionally available nahi; gated active checks ke liye `--active` plus second confirmation use hoti hai.
- **HTML report:** Markdown ya JSON generate karke trusted external renderer use karein.
- **Asset list:** `AssetType` enum dekhein; runtime par detected types report header mein show hote hain.

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
