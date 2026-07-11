# CYGNUS engineering and safety notes

This file makes intentional limitations and safety boundaries reviewable rather than implicit.

## Gates and runtime behavior

1. **No pre-authorization connectivity check.** Online/offline detection necessarily happens after authorization and scope validation; probing before that would violate the mandatory gate. Mode is printed immediately after runtime fingerprinting.
2. **Scope matching does not resolve domains.** A permitted domain is matched textually; its resolved IP need not also appear in scope. This prevents a DNS query before authorization and avoids incorrectly rejecting CDN-backed domains. Exact domains do not include children; use `*.example.com` intentionally.
3. **Audit is append-only at application level, not tamper-proof.** JSONL records every invocation that reaches execution. Protect/ship the file using OS controls or a log collector if non-repudiation is required.
4. **Active gate is implemented, but built-ins are passive.** `--active` plus a second confirmation is required for any plugin marked `requires_active`. There are currently no built-in exploit/login/write plugins.

## Protocol boundaries

- HTTP checks issue GETs and a synthetic `Origin`; reflection uses the inert marker `CYGNUS_REFLECT_7f3a`, not script/SQL/template payloads.
- The header check proves header absence, not exploitability. It is low impact and cannot form a chain unless a separate confirmed dependency rule is satisfied.
- CORS is confirmed only on reflected arbitrary origin, or wildcard plus credentials. It does not access authenticated user data.
- FTP sends `FEAT` after reading the greeting. Anonymous access is reported only if the service advertises it. **No `USER`/`PASS` command is sent.**
- IoT default-credential logic only searches captured onboarding/banner text. It is always manual-verification evidence; no login is attempted, even when `--active` is supplied.
- Kubernetes and Docker checks call identity/health endpoints only. No enumeration, exec, image pull, or mutation.
- Storage checks request the public endpoint and recognize listing structures. No object is downloaded beyond the bounded response and no policy is changed. Credentialed providers are not silently inferred; future credential support must consume explicit operator input.
- TCP/HTTP capture is capped (4 KiB evidence; HTTP transport reads at most 64 KiB). Redirects follow Python's standard HTTP behavior, so scope owners should include/control redirect destinations; a future release should add per-hop scope enforcement before use across untrusted redirectors.
- No broad port scan is performed. CYGNUS connects to the explicit port (or scheme default) only. This trades coverage for low-impact behavior.

## Evidence and scoring

- Modules emit candidates, never severity/confidence. `ScanEngine` computes both from evidence strength and impact.
- Empty evidence drops the candidate. Captures are safely truncated.
- Weak evidence caps severity at Medium and is routed to manual verification.
- Exact banner/CVE matches are also routed to manual verification because vendor backports are common.
- Static candidates are always `STATIC/UNCONFIRMED`, regardless of pattern strength, and do not enter confirmed counts.
- Secret matches are redacted in evidence. Source files themselves remain untouched.
- Chain rules are a fixed dependency graph over confirmed tags. There is no title concatenation or probabilistic chain generation.

## CVE cache

`cygnus/data/cve_cache.json` is a deliberately small curated cache sourced from the NIST NVD CVE API 2.0, with direct NVD detail links and a cache date. Matching requires both product and exact version text. It is not a complete vulnerability database, does not model distro backports, and must be refreshed/reviewed before production use. A miss is never reported as a clean bill of health.

## Fingerprint shortcuts

Classification uses observed DNS, accepted TCP connections, banners, TLS certificate digest, HTTP content/headers, hostname provider signatures, or local file metadata. Confidence reflects those signals. The initial implementation does not enumerate all 70+ taxonomy labels from a single target; the enum/schema and plugin gate are extensible, while only types with defensible signals are emitted. Unknown is preferred over speculative classification.

TLS capture uses an unverified handshake to collect the leaf certificate digest; it does not claim certificate validity. HTTP signatures are intentionally narrow and may miss customized products.

## Testing boundary

Mocks cover the major implemented transport families: web, FTP, and an exposed container dashboard. Cloud/provider APIs and real credential paths are not called by tests. The anti-static regression compares intentionally different vulnerable/secure fixtures; two genuinely equivalent targets are allowed to have equal severity counts in production, although their full reports retain target/evidence differences.

## Concurrent execution and fail-closed output validation

- Applicable plugin coroutines run concurrently with `asyncio.gather`; discovery order is preserved in the module ledger and each module still performs its own protocol request.
- Exceptions remain isolated as `ModuleResult(status="error")` and cannot erase evidence produced by unrelated checks.
- Every scored finding receives a separate timezone-aware UTC `observed_at`; its stable ID remains derived from name/component/evidence rather than time.
- The final validator discards a finding before counts and chains if evidence is empty, its timestamp/status is invalid, or its asset type is absent from the fingerprint profile.
- `AUDIT_REPORT.md` records the exact historical and current fixed-output search. The claimed legacy 96-item implementation is not present in the supplied baseline and no fictional file location is asserted.

## v3.3 usability and analysis boundaries

- `python -m cygnus`, positional targets, and `-t/--target` are equivalent; legacy commands remain compatible.
- `--init-scope` only writes the normalized supplied target and refuses to overwrite an existing file. It performs no network access and does not grant authorization by itself.
- `--recon` still requires authorization and scope, then stops after evidence-bearing fingerprinting.
- `--list-assets` and `--list-modules` are local introspection utilities and do not access a target.
- HTTP redirects are captured but not automatically followed, preventing a scoped URL from silently redirecting checks to another host.
- Cookie, authorization, and API-key response headers are redacted in report captures.
- OpenID and GraphQL checks issue bounded metadata queries only. GraphQL introspection is weak/manual evidence, not a confirmed exploit.
