# SentinelScan — World Monitor Security Assessment & Controlled Retest

**World Monitor finding status:** No authorized local World Monitor instance was available in the build environment, so this package contains scaffolding and a synthetic assessment lab only; it does not claim a real World Monitor vulnerability.

SentinelScan is an authorized, local-first application-security assessment platform for a locally deployed or staging **World Monitor** instance. It evaluates authentication, authorization, input validation, API security, client-side controls, secure communication/CORS, and data/privacy exposure; records evidence; and supports controlled PoC, remediation retest, and regression testing.

## Architecture

- **Frontend:** `frontend/index.html` — Security Center dashboard.
- **Backend:** `backend/server.py` — assessment API, localhost target enforcement, evidence hashing, audit logging, retest lifecycle.
- **Assessment Lab:** `assessment_lab/vulnerable_app.py` — isolated synthetic vulnerable app on `127.0.0.1:8100`.
- **Evidence:** `backend/sentinelscan_audit.jsonl` — append-only JSONL audit trail created at runtime.
- **State:** `backend/security_state.json` — persistent assessment state created at runtime.

## Scope

1. Authentication and session management.
2. Authorization and access control.
3. Input validation and data handling.
4. API security.
5. Client-side security controls.
6. Secure communication mechanisms and CORS behavior.
7. Data storage and privacy protections.

## Automated controls

| ID | Control |
|---|---|
| AUTH-001 | Authentication enforcement |
| AUTHZ-001 | API authorization enforcement |
| INPUT-001 | Input validation |
| API-001 | HTTP method enforcement |
| CLIENT-001 | Client-side credential exposure heuristic |
| CORS-001 | CORS origin enforcement |
| DATA-001 | Debug endpoint exposure |

Every result records request/response, expected behavior, actual behavior, verdict, timestamp, source, and a SHA-256 evidence hash.

## Vulnerability deliverable format

For each confirmed finding, document:

- Vulnerability title
- Description
- Affected component
- Severity and CVSS when defensible
- Preconditions
- Steps to reproduce
- Safe proof of concept
- Evidence
- Business impact
- Remediation
- Independent retest result
- Regression result

## Controlled PoC

The Assessment Lab is deliberately separate from World Monitor. `GET /admin` returns a synthetic admin marker before remediation and `403 Forbidden` after the lab fix. This demonstrates the complete lifecycle without claiming that World Monitor contains the synthetic vulnerability.

## Safety constraints

- Test only authorized local/staging systems.
- Public/remote targets are rejected by the backend.
- Do not affect production users or data.
- PoC validation is controlled and non-destructive.
- No credential guessing, credential theft, persistence, or unrelated exploitation.
- Follow applicable laws, policies, and ethical hacking requirements.

## Run

### Windows

Double-click:

```text
START_SENTINELSCAN.bat
```

It starts the lab on `127.0.0.1:8100`, SentinelScan on `127.0.0.1:8000`, and opens the dashboard.

### Manual

```bash
python assessment_lab/vulnerable_app.py
python backend/server.py
```

Then open `http://127.0.0.1:8000/`.

To assess World Monitor, start an authorized local/staging instance separately, then enter its localhost URL in the dashboard.

## Demonstration

1. Start SentinelScan.
2. Start World Monitor locally if available.
3. Enter its localhost URL.
4. Click **CHECK WORLD MONITOR**.
5. Review the seven automated controls and evidence hashes.
6. Use the Assessment Lab **RETEST** button to demonstrate the synthetic finding.
7. Click **FIX LAB**.
8. Run **RETEST** again.
9. Run **REGRESSION TEST**.

## Important limitation

This project does **not** manufacture a World Monitor vulnerability. A real finding requires evidence from the authorized target that violates an applicable security expectation. The controlled lab is only a reproducible demonstration environment.

## References

- https://github.com/koala73/worldmonitor
- https://github.com/koala73/worldmonitor/blob/main/ARCHITECTURE.md
- https://github.com/koala73/worldmonitor/blob/main/docs/getting-started.mdx
- https://github.com/koala73/worldmonitor/blob/main/SECURITY.md

## Product-grade upgrades in this build

This build adds a working security-product layer on top of the assessment workflow:

- PASS / FAIL / REVIEW / MANUAL control states.
- Security score derived from automated control results.
- Finding lifecycle storage with status, severity, CVSS, OWASP mapping, impact and remediation.
- Evidence viewer with request/response information and SHA-256 integrity hash.
- Scan history for recent assessments.
- HTML security report generation from persisted state.
- Controlled Assessment Lab finding with CVSS, retest, FIX LAB and regression lifecycle.
- Stronger loopback target validation using DNS resolution rather than hostname text alone.
- Target scope protection that rejects non-loopback resolution.

The project remains evidence-first: a synthetic Assessment Lab finding is never presented as a confirmed World Monitor vulnerability.

## Hardened Build Additions

This build adds an authenticated local control plane and additional hardening:

- Per-install bearer token stored in `backend/.session_token` with restrictive file permissions.
- Protected state, history, audit verification, scan, lab, and report APIs.
- Constant-time token comparison.
- Strict loopback-only target validation using DNS resolution and IP-address checks.
- Pinned requests to the resolved loopback address.
- Redirects are not followed by the assessment HTTP client.
- Userinfo in target URLs is rejected.
- Request-body size limits.
- Origin allowlisting for browser POST requests.
- Hash-chained audit records with an independent verification endpoint.
- Atomic state writes with restrictive permissions.
- Explicit `ERROR` state for transport failures instead of treating failed requests as PASS.
- `tools/self_scan.py` for local hardening and lifecycle verification.
- `SELF_SCAN.bat` for a Windows self-test.

### Self-scan

From the project root:

```text
python tools/self_scan.py
```

The self-scan verifies authentication, loopback target enforcement, userinfo rejection, audit-chain integrity, and the synthetic lab's open → fixed → regression lifecycle. It does not target public systems.

## Frontend hardening

- `frontend/index.html` contains no inline `onclick` handlers.
- All UI actions are wired with `addEventListener` from `frontend/app.js`.
- Rendering uses DOM node creation and `textContent` rather than injecting untrusted HTML.
- The dashboard CSP uses `script-src 'self'`; inline JavaScript is not permitted.
- The report page uses `script-src 'none'` because it is static HTML.

### Token storage limitation

The dashboard currently stores the local bearer token in `localStorage` for convenience. This is **not equivalent to an HttpOnly, Secure, SameSite cookie**: JavaScript running in the page origin can read the token, so an XSS compromise could expose it. This is acceptable only for the controlled local assessment dashboard and should not be treated as a production session-management pattern. For a production deployment, prefer a server-managed session with an HttpOnly/Secure/SameSite cookie, CSRF protection where applicable, short expiry, rotation, and server-side revocation.

## Audit-chain external anchor

SentinelScan writes the hash-chained audit trail to `backend/sentinelscan_audit.jsonl` and maintains a separate signed manifest at `evidence/audit_anchor.json`. The manifest records the audit file SHA-256, record count, first/last chain hashes, timestamp, and an HMAC-SHA256 signature. The signing secret is stored separately in `backend/.audit_anchor_secret` and is excluded from source control/runtime packaging.

The local signed manifest is an **integrity anchor, not an independent trust boundary**: anyone who controls both the audit directory and signing secret could replace both. For stronger evidence, export/copy the manifest to an independent evidence store or signing service after the assessment.

## HTTPS pinning behavior

For HTTPS targets, SentinelScan resolves the approved hostname to a loopback IP, opens the TCP socket to that resolved IP, then performs TLS using the **original hostname as SNI and certificate-verification name**. Redirects are not followed. This prevents a hostname/IP substitution while avoiding the incorrect pattern of validating a certificate against the pinned IP address.

## Self-scan behavior

`tools/self_scan.py` calls each HTTP endpoint used by the harness at most once. It tests the resolver directly for the userinfo case, validates the signed audit anchor, performs the synthetic lab open → fix → regression lifecycle, checks audit tamper detection, and resets the lab state directly in `finally` so cleanup does not require an additional endpoint call.

## Real World Monitor finding requirement

The Assessment Lab finding (`LAB-AUTHZ-001`) is synthetic. It is not evidence against World Monitor.

If the assignment requires a **real World Monitor vulnerability**, an authorized local/staging World Monitor instance must be running and reachable on a loopback URL. SentinelScan can then scan that instance and persist the resulting evidence. Do not claim a World Monitor finding based only on the synthetic lab or on an unexecuted scanner result. If no local World Monitor instance is available, this package contains scaffolding only and makes that limitation explicit.

## 2026-10-05 3D UI deployment fix

The SentinelScan frontend now restores the 3D intelligence presentation: a WebGL globe, country boundary layer, clickable country markers, rotation, scroll zoom, regional panel, and Security Center modal.

The country boundary layer is loaded from the open `datasets/geo-countries` GeoJSON source in the browser. Three.js is loaded from jsDelivr. The backend CSP explicitly allowlists those two sources for the presentation layer.

### Important deployment behavior

SentinelScan remains **loopback-only for the actual target assessment**. A Render-hosted SentinelScan instance cannot reach `127.0.0.1:3000` on the operator's laptop. Therefore:

- Use the deployed Render UI for the visual/demo presentation.
- Run SentinelScan locally beside the authorized local World Monitor instance for the real target assessment.
- Do not change the loopback restriction merely to make a public scanner.
- The controlled Assessment Lab is separate and must never be described as a World Monitor vulnerability.
