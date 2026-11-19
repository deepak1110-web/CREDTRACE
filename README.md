# CREDTRACE Phase 1

**Credential Tracking & Digital Forensics Platform** — “From Credential Compromise to Digital Evidence.”

This is a consent-based browser simulation using fictional records and synthetic credentials. It does not access real systems, devices, files, cameras, microphones, or third-party services.

## Included

- Four routes: `/`, `/company`, `/attacker`, `/investigator`
- Company portal: synthetic credential issuance (secret displayed once), inventory
- Simulator: credential validation, synthetic record reads, vendor list, restricted export denial, heartbeat
- PostgreSQL (Neon) deployment support; SQLite for quick local smoke testing
- Event storage and SHA-256 hash chain with integrity endpoint
- Investigator login, summary, event feed, alerts, commands, PDF report
- Two-way WebSocket command/acknowledgement (single-instance registry)
- Explainable risk rules, MITRE ATT&CK simulation mapping, graph data endpoint
- Incident CRUD/status/notes, alert status history, evidence custody actions
- Credential states: ACTIVE, SUSPENDED, REVOKED; backend blocks inactive credentials
- Argon2 credential-secret hashing; configured passwords verified via Argon2
- Rate limiting, input schemas, secure response headers, safe text rendering

## Local quick run (optional)

Python 3.11+ is recommended. Local run uses SQLite unless `DATABASE_URL` is set.


1. `python -m venv .venv`
2. Windows: `.venv\\Scripts\\activate`
3. `pip install -r requirements.txt`
4. Set environment variables (PowerShell example):
   ```powershell
   $env:ADMIN_PASSWORD = "Use-a-long-random-demo-password!"
   $env:COMPANY_PASSWORD = "Use-another-long-demo-password!"
   $env:APP_SECRET = "generate-a-long-random-secret-value"
   uvicorn credtrace_phase1:app --reload
   ```
5. Open `http://127.0.0.1:8000`.


## Deployment: GitHub + Neon + Render

1. Create a GitHub repository (for example `credtrace-phase1`).
2. Upload all files from this project folder: `credtrace_phase1.py`, `requirements.txt`, `README.md`, and `render.yaml`.
3. In Neon, create a PostgreSQL project/database. Copy the connection string; ensure it includes SSL (`sslmode=require`).
4. In Render, create a new Web Service from the GitHub repo. The included `render.yaml` defines the build and start commands.
5. In Render environment variables, set:
   - `DATABASE_URL`: Neon connection string
   - `ADMIN_PASSWORD`: long random investigator password
   - `COMPANY_PASSWORD`: long random company portal password
   - `APP_SECRET`: long random value (Render can generate it)
6. Deploy. Check `/health`; it should return JSON status `ok`.
7. Open the deployed service's public URL:
   - Landing: `/`
   - Company: `/company`
   - Simulator: `/attacker`
   - Investigator: `/investigator`
8. Log into Company with username `company` and your `COMPANY_PASSWORD`; issue a synthetic secret and copy it (shown once).
9. On laptop 1, open `/attacker`, paste the synthetic secret, enter a browser/device label, and click Validate/connect. Try read, vendor listing, restricted export.
10. On laptop 2, open `/investigator`, login with username `investigator` and `ADMIN_PASSWORD`, refresh events, and try risk, alerts, graph, MITRE, custody and PDF. Use the simulator session ID displayed in simulator event output to send commands.


## API quick reference

- `POST /api/login` — company/investigator login
- `POST /api/company/credentials` — issue a synthetic credential (company auth)
- `GET /api/company/credentials` — company credential inventory
- `POST /api/sim/action` — synthetic credential-backed simulation request
- `GET /api/investigator/summary`, `/events`, `/alerts`, `/risk/{credential_id}`, `/mitre`, `/graph`, `/custody`, `/incidents`, `/commands`, `/integrity`
- `PATCH /api/investigator/credentials/{id}/{ACTIVE|SUSPENDED|REVOKED}` — lifecycle action
- `PATCH /api/investigator/alerts/{id}` — alert acknowledgement/assignment/escalation/resolution
- `POST /api/investigator/commands` — send harmless simulator command
- `GET /api/investigator/report.pdf` — PDF report
- `WS /ws/investigator`, `WS /ws/simulator/{session_id}`

## Risk scoring formula

Rules are event-type based and explainable; event IDs are shown as contributors. The risk score is capped at 100 and levels are: 0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical.

- Authentication failure: +5 each, cap 20
- Revoked-credential attempt: +25 each, cap 50
- Restricted export: +20 each, cap 40
- Unusual frequency: +10, cap 20
- Multiple active sessions: +15, cap 15
- Suspicious sequence: +15, cap 15
- Credential reuse: +15, cap 15

The event-type classification is intended to avoid counting the same event across multiple rule buckets. The score is heuristic simulation risk, not calibrated real-world likelihood.


## MITRE ATT&CK mappings

Mappings are returned only when event evidence exists and are labeled simulated. The current illustrative mapping includes T1110 Brute Force (failed attempts), T1078 Valid Accounts (synthetic credential accepted), T1048 Exfiltration Over Alternative Protocol (restricted export request; blocked, so this mapping is illustrative and not evidence of exfiltration), and T1087 Account Discovery (vendor enumeration). Validate mappings with the ATT&CK knowledge base before using in a real report.


## Test instructions

Install requirements, then run:

```bash
python -m unittest -v
```

Tests are local SQLite/API smoke tests; a real deployment, WebSocket cross-device test, database failover, and free-tier behavior still require deployment validation.

## Known limitations and security notes

- This is a hackathon prototype. Do not use real credentials, real records, or expose it to the public internet without a security review.
- Passwords are environment variables; Argon2 verification is used. However, current CSRF coverage is incomplete for cookie-authenticated write routes. Use a separate CSRF token/header implementation before production.
- Credential secrets are hashed at rest and only shown on issuance, but a valid synthetic secret is bearer-like by design in this demo.
- The in-memory WebSocket connection registry is single-instance and not shared between multiple service replicas. Render instance restart can drop live sockets; persisted event polling is the recovery path.
- Event hash chain is tamper-evident, not immutable. An administrator with database access could modify events and recompute hashes. External anchoring/WORM storage is not included.
- Network peer and user-agent metadata are observations, not identity proof. IP addresses and browser identifiers cannot attribute a person.
- Browser-generated device label is user-provided in this simplified prototype, not a fingerprint.
- Login UI currently relies on environment-provided passwords and basic username conventions. Add stronger account provisioning and session revocation for production.
- Risk scoring is explainable but heuristic; score weights are demonstration choices and not validated against threat data.
- PDF report has actual database contents but currently provides a compact summary and does not yet include every advanced field (e.g. detailed per-credential risk breakdown, full network/device section, complete export audit).
- Several requested investigator operations are exposed through APIs but the dashboard UI is simplified; graph endpoint returns graph data but UI displays it as evidence JSON rather than a force-directed visualization.
- Alert/incident/audit tables exist; incident linking uses IDs supplied by investigator and does not yet validate all linked entity IDs.
- `CREDENTIAL_REVOKED` is a UI notice command; actual credential state change is performed via the lifecycle API.
- Free tiers may sleep, cold-start, or suspend services/database resources. Public HTTPS is provided by Render when deployed; this package has not been deployed from this environment.

## Acceptance status

Routes, deployment configuration, and local automated checks must be tested before claiming completion. No live Render deployment or two-laptop test is performed by this generated package.

## Advanced module coverage (prototype status)

| Module | Current prototype status |
|---|---|
| Risk scoring | Explainable rule-based 0–100 calculation with event-type caps and contributor IDs |
| MITRE mapping | Evidence-gated simulated mappings (T1110 requires 3 failures; T1078 requires accepted synthetic credential evidence) |
| Attack graph | Backend graph JSON links synthetic credential/session/device/event/fictional-resource/alert nodes; UI currently renders JSON, not a draggable graph |
| Chain of custody | Records create/view/export actions and separate SHA-256 custody chain verification; limitations noted |
| Incident management | Create, list, update status/severity/assignee, add notes; linked identifiers stored but not fully validated |
| Credential lifecycle | Issued/active/suspicious/compromised/revoked/expired/suspended states accepted; non-ACTIVE states rejected by simulator; expiration field exists but automatic TTL issuance is not implemented |
| PDF report | Database-backed timeline, counts, alert/credential/incident/custody summaries, event/custody integrity status, risk explanation |
| Alert management | Acknowledge/assign/escalate/resolve status API, action history, severity filter |
| Live monitoring | WebSockets, signed simulator connection token, investigator cookie auth, reconnect + event-feed recovery on investigator reconnect |
| Security hardening | Argon2 credential hashing, signed role session cookie, backend role checks, rate limiting, parameterized ORM, response headers, validation |

**Not yet implemented/verified:** company ticket submission/history persistence, full draggable graph visualization, automatic credential expiration scheduling, CSRF token enforcement for every cookie-authenticated mutation, robust session revocation/logout invalidation, multi-instance WebSocket broker, full export-history subrecords, external immutable evidence anchoring, and comprehensive runtime/production security testing. The API/UI are a hackathon prototype, not a production SOC platform.

## Test results from this build session

Executed locally with SQLite/TestClient: **13 tests passed**. Coverage included all four page routes and health check; company credential issue; simulated validate/read/vendor/restricted-export requests; risk score threshold; alert acknowledgement; incident creation; credential revocation and rejection after revocation; event hash-chain and custody-chain integrity; PDF generation; MITRE/graph endpoints; and WebSocket command delivery/acknowledgement. Embedded JavaScript syntax was also checked with Node.js. Neon and Render deployment, cross-laptop public-HTTPS operation, free-tier sleep/recovery, and production security review remain untested.
