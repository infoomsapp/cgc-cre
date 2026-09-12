# CGC Core

Cognitive Governance Cycle — Olympus Mont Systems' AI decision-governance engine.

Every AI decision routed through CGC Core is: pre-filtered against agent/RBAC/scope rules, scored by four independent governance modules, evaluated against compliance frameworks, cryptographically sealed with a non-repudiable signature (Proof of Decision), and written to an immutable, hash-chained audit trail. Consumed today by LedgiProof and LedgiProof Tax Pro as a server-to-server governance layer for AI-assisted transaction classification, and by ControlMiles for crash monitoring and trip-governance sealing.

## Architecture

```
request → PreFilter → SCM (security gate) → ┬→ PAN (pattern analysis)
                                              ├→ ECM (evaluation/calibration)
                                              ├→ PFM (probability/failure modeling)
                                              ├→ SDA (standards/domain adherence)
                                              ├→ weighted aggregation
                                              ├→ ComplianceEngine (EU AI Act / NIST RMF)
                                              ├→ PoD (cryptographic seal)
                                              ├→ TCO (immutable audit log)
                                              └→ response
```

| Module | Path | Role |
| --- | --- | --- |
| PreFilter | `app/modules/prefilter/` | Agent/RBAC/scope gate, first line of defense |
| SCM | `app/modules/scm/` | Security & Cryptographic Module — signing, encryption, KMS |
| PAN / ECM / PFM / SDA | `app/modules/{pan,ecm,pfm,sda}/` | The four scoring modules aggregated into a decision |
| ComplianceEngine | `app/modules/compliance/` | Evaluates decisions against EU AI Act / NIST RMF criteria |
| PoD | `app/modules/pod/` | Proof of Decision — pre-delivery cryptographic non-repudiation |
| TCO | `app/modules/tco/` | Immutable, hash-chained audit trail |
| LOOP | `app/modules/loop/` | Orchestrates the full cycle above (`cgc_loop.py`) |
| Guard | `app/modules/guard/` | Rate limiting, credential-stuffing/payload detection, internal misuse detection |
| Flow Scoring | `app/modules/flow_scoring/` | Rolling business-flow health signals per connected app |
| JLA | `app/modules/jla/` | Governance calibration data loader (`cgc_jla.*` schema) |
| Launch Readiness | `api/v1/endpoints/launch_readiness.py` | Play Store/App Store submission-readiness tracking per app_source |

`app/Core/` holds cross-cutting infrastructure: `db/` (Postgres connection pooling + schema provisioning), `auth/` (JWT + session auth), `tenant/` (plan/quota management), `logging/`, `config/`.

## Data & tenant isolation

Postgres (Supabase), schemas `cgc_pod` / `cgc_tco` / `cgc_guard` / `cgc_jla` / `cgc_auth`. Two application-level DB roles:

- **`postgres`** — DDL, boot-time schema provisioning, and every cross-tenant admin read (dashboards, billing). Bypasses RLS by design.
- **`cgc_app`** — real Row-Level-Security-enforced role for tenant-scoped writes/reads (PoD's 3 tables, the 4 tenant-scoped `cgc_guard` tables). `cgc_tco.audit_trail` is deliberately excluded — it's one global sequential hash chain, not per-tenant, so its block-numbering query needs unrestricted visibility; RLS there would corrupt the chain.

## Running locally

```
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Without `DATABASE_URL` set, `Database` falls back to local JSON files under `data/` (dev-only — not safe on a read-only filesystem, e.g. Vercel outside `/tmp`).

## Testing

```
pip install -r requirements-dev.txt
python -m pytest -v
```

Runs against a disposable Postgres container (see `tests/conftest.py`). CI (`.github/workflows/test.yml`) runs the same suite on every push/PR to `main`, against a real Postgres service container — not mocks.

## Deployment

Vercel only (Railway was retired 2026-08-19). `api/index.py` re-exports the FastAPI app for Vercel's native Python runtime — no `vercel.json`, the dashboard's framework preset handles it. `requirements-vercel.txt` is a trimmed subset of `requirements.txt` (drops heavy, unused-in-this-codebase packages) to stay under Vercel's function size limit.

## Required environment variables

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres connection string, `postgres` role — DDL + admin reads |
| `CGC_DATABASE_URL` | Same Postgres, `cgc_app` role — tenant-scoped RLS-enforced operations |
| `CGC_APP_ROLE_PASSWORD` | Password for the `cgc_app` Postgres role |
| `JWT_SECRET` | Session token signing |
| `CGC_SCM_RSA_PRIV_V1` / `CGC_SCM_RSA_PUB_V1` | SCM's RSA-PSS-SHA256 signing keypair (base64 PEM) |
| `CGC_SCM_ENC_MASTER_V1` | SCM's local encryption master key |
| `CGC_POD_RSA_PRIV_V1` / `CGC_POD_RSA_PUB_V1` | PoD's own signing keypair — without these, PoD signs with a fresh ephemeral key every cold start, breaking non-repudiation across restarts |
| `CGC_SERVICE_API_KEY` | Long-lived bearer credential for server-to-server callers (LedgiProof, ControlMiles) and scheduled jobs |

Optional:

| Variable | Purpose |
| --- | --- |
| `AWS_KMS_MASTER_KEY_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Switches SCM from local software signing to AWS KMS (FIPS 140-2 Level 2 validated HSMs via the FIPS endpoint by default — see `CGC_KMS_USE_FIPS_ENDPOINT`). Unset = local signing. |
| `SLACK_BOT_TOKEN`, `SLACK_MONITOR_CHANNEL` | Error-monitor alerting |
| `SUPABASE_MANAGEMENT_PAT` | Enables the Supabase-advisors signal in Launch Readiness's `/refresh` endpoint |
| `GUARD_HARD_MODE_PAYLOAD`, `GUARD_HARD_MODE_STUFFING` | Promotes the payload/credential-stuffing detectors from soft-flag (log only) to hard-block |
| `CGC_GUARD_*_RETENTION_DAYS` | Per-table retention windows for `cgc_guard`'s telemetry tables |
| `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_REDIRECT_URI` | Enables "Continue with Google" on `/dashboard/account` (see `GET /auth/google/status`). Create a Web application OAuth client in Google Cloud Console with `GOOGLE_OAUTH_REDIRECT_URI` (e.g. `https://cgc-cre.vercel.app/auth/google/callback`) as an authorized redirect URI. Unset = the button stays hidden, no error. |

## API surface

Interactive docs at `/docs` (Swagger) once running. Key routes: `POST /governance/decision` (the main entry point), `POST /auth/signup` / `signin`, `GET /verify/{decision_id}` (unauthenticated forensic proof lookup, gated by knowing the decision_id + tenant), `GET /dashboard` (operator UI), `GET /health`, `GET`/`PUT /calibration/{module}/{area}` + `GET /calibration/changelog/list` (versioned history of PAN/ECM/PFM/SDA scoring-rule changes — every update is admin-only and always changelogged in the same request, no code path updates calibration silently), `GET /governance/scoring-methodology` (the exact aggregation formula and every area+sensitivity weight, for an auditor who doesn't want to read source), `GET /compliance/glba-safeguards` (FTC Safeguards Rule self-assessment — see Known Gaps below for why GLBA, not HIPAA/FINRA, is the framework that actually applies), `POST /tenants/self-signup` (any authenticated non-admin user can claim a brand-new, not-yet-taken `app_source` and get its API key — reserved first-party names can't be self-claimed, and this can't touch any other tenant's data), `GET /tenants/my-apps` + `POST /tenants/my-apps/{app_source}/keys/regenerate` + `POST .../keys/{key_id}/revoke` + `.../billing/checkout-link` + `.../billing/portal-link` (customer self-service, ownership-checked against `created_by` rather than `require_admin` — the backend for `GET /dashboard/account` below), `GET /dashboard/account` (the one customer-facing settings page — claim an app, see your own keys, regenerate/revoke them, upgrade/manage your own billing; deliberately standalone, not linked from the internal-ops dashboards' topnav), `GET`/`POST`/`DELETE /tenants/my-apps/{app_source}/webhook` (register a URL to receive an HMAC-SHA256-signed POST on every decision for your app_source instead of polling — best-effort delivery, 5s timeout, no retry queue yet), `POST /admin/keys/rotation-check` (require_admin_or_service, cron-callable — Slack-alerts on any active key older than 90 days; never rotates anything itself), `GET /docs/getting-started` (a real, hand-written integration guide with curl examples — signup, self-signup, first decision, webhook signature verification, rate limits — complementing, not duplicating, the auto-generated Swagger at `/docs`), `GET /tenants/my-apps/{app_source}/decisions` (customer-facing decision history — reuses TCO's existing `get_audit_trail_by_app`, capped at the 100 most recent, ownership-checked like the rest of the `/tenants/my-apps/*` family — the backend for `/dashboard/account`'s Decision History tab), `GET /auth/google/status` + `GET /auth/google/login` + `GET /auth/google/callback` ("Continue with Google" — Google OIDC login for `/dashboard/account`, no auth dependency since these are login entry points; see Required environment variables for the 3 vars that turn it on), `GET /auth/saml/lookup` + `GET /auth/saml/{domain}/login` + `POST /auth/saml/{domain}/acs` + `GET /auth/saml/metadata` (enterprise SAML SSO — Okta/Azure AD/OneLogin — one connection per customer email domain, admin-provisioned via `POST`/`GET /admin/saml-connections`, no auth dependency on the login-flow routes since they're entry points; uses `python3-saml` for all cryptographic verification, never hand-rolled).

## Known gaps

These are the real, currently-unmitigated gaps as of 2026-09-11 — kept accurate deliberately, since this file is the first thing an external auditor or acquirer would check against the actual code:

- **No third-party security audit or penetration test.** Only internal self-testing has been done (SQL injection, auth bypass, rate-limiting, email-vector checks) — no independent firm has verified this.
- **`AWS_KMS_MASTER_KEY_ID` isn't provisioned** — SCM signs locally, not through a FIPS-validated hardware boundary.
- **No ISO/IEC 42001, SOC 2, or other independent certification.** ComplianceEngine evaluates against EU AI Act / NIST RMF / GLBA Safeguards Rule criteria internally, but nothing here is externally certified.
- **No third-party cryptographic audit of PoD/TCO's hash-chain design** — nothing external has verified it's actually tamper-resistant against an insider with direct Postgres access.
- **The area+sensitivity decision-weighting matrix (`DECISION_WEIGHTING_MATRIX`, `cgc_loop.py`) is still hardcoded in source**, versioned only by git — not by `cgc_calibration_changelog` the way the underlying PAN/ECM/PFM/SDA calibration is. `GET /governance/scoring-methodology` exposes it faithfully, but changing it still means a code change + redeploy, not an audited API call.
- **Several GLBA Safeguards Rule elements are genuinely `MANUAL_REVIEW_REQUIRED`** (Qualified Individual designation, written risk assessment, written security program, service-provider oversight from the covered entity's side) — organizational/personnel facts no code can attest to, honestly reported as such by `GET /compliance/glba-safeguards` rather than assumed. `incident_response` and `periodic_testing` currently report `FAIL` for real (Slack alerting isn't configured everywhere, and no third-party pentest exists — see above).
- **Zero external paying customers.** Every current consumer (LedgiProof, LedgiProof Tax Pro, ControlMiles) is the same operator's own product — no independent market validation yet.
- **SAML connections are admin-provisioned, not self-service.** A customer's own IT admin can't configure their Okta/Azure AD connection through the dashboard yet — they send their IdP metadata (Entity ID, SSO URL, certificate) and CGC Core's operator sets it up via `POST /admin/saml-connections`. A self-service config form is a reasonable next step once a real enterprise customer asks for it.
- **No IdP-initiated SSO or JIT role/group provisioning.** SAML login here is SP-initiated only (start at CGC Core, not from a tile inside the customer's Okta dashboard); a new SAML user gets the same default `user` role Google/password signup gets, with no group-to-role mapping.

Already mitigated, despite sometimes being assumed otherwise:
- A real automated test suite (37 tests across 8 files) and CI (GitHub Actions, running against a live Postgres service container on every push/PR to `main`) have existed since 2026-08-23 — not "verified live against production only."
- A versioned changelog for the PAN/ECM/PFM/SDA scoring calibration (`cgc_calibration_changelog`, `/calibration/*` — see API surface above) has existed since 2026-09-11. Every change to a scoring rule is admin-only and requires a `reason`; nothing updates calibration without also writing its own history entry.
- `GET /governance/scoring-methodology` (since 2026-09-11) explains, in one response, the exact formula and every weight used to turn module scores into an APPROVE/REJECT/REQUIRE_HUMAN decision — no need to read `cgc_loop.py` to audit how a decision was reached.
- **Google OIDC login** (since 2026-09-12): `AuthSystem.login_federated()` + `/auth/google/*` — CSRF-protected via a signed state cookie, ID token verified against Google's real JWKS via the official `google-auth` library (never hand-rolled), auto-provisions an account with a permanently-unusable random password on first login. Verified live up to the Google-consent boundary (status/login/CSRF rejection all correct); the actual browser consent screen needs the user's own Google Cloud OAuth client credentials to exercise end-to-end.
- **Enterprise SAML SSO** (since 2026-09-12): `/auth/saml/*` + `cgc_saml_connections` — one Identity Provider connection per customer email domain, all cryptographic assertion verification via `python3-saml`/`xmlsec` (never hand-rolled), reuses the same `login_federated()` session-issuing path Google uses. Verified live against production: admin can create a connection, `/auth/saml/lookup` correctly reports availability, `/auth/saml/{domain}/login` redirects to that domain's real IdP with a well-formed `AuthnRequest`, `/auth/saml/metadata` returns valid SP metadata XML. The actual signed-assertion round-trip needs a real Okta/Azure AD trial tenant to exercise end-to-end — same category of user-side dependency Google's consent screen has.
- The EU AI Act checks in `ComplianceEngine.validate_eu_ai_act` are real logic as of 2026-09-11, not hardcoded placeholders — see the method's own docstring for exactly which 4 of the 7 requirements are runtime-verifiable (and are), and why the other 3 honestly report `MANUAL_REVIEW_REQUIRED` instead of a fabricated PASS.
- `GET /compliance/glba-safeguards` (since 2026-09-11) is a real FTC Safeguards Rule self-assessment scoped to what actually applies (GLBA, via LedgiProof/LedgiProof Tax Pro as tax preparers) — HIPAA and FINRA are explicitly reported as not applicable to any current consumer, with the regulatory reasoning, rather than building decorative checklists for frameworks nothing here is subject to.
- **Self-serve tenant onboarding** (since 2026-09-11): `POST /tenants/self-signup` lets any authenticated non-admin user (via the existing `/auth/signup`) claim their own brand-new `app_source` and get an API key + FREE billing stub, with no admin action needed. Reserved first-party names can't be self-claimed, an already-claimed `app_source` returns 409, and format/rate limits apply — verified live end-to-end (claim, collision, reserved-name, bad-format, unauthenticated all return the correct status).
- **A real customer-facing settings page** (`GET /dashboard/account`, since 2026-09-11): claim an app, view your own keys, regenerate/revoke them, upgrade or manage your own billing — all ownership-checked (`created_by` match), not `require_admin`. Before this, self-signup only existed as an API call with no UI, and there was no way for a non-admin to ever see or rotate their own key again after the one-time reveal. Verified live: two disposable non-admin accounts, cross-account ownership correctly rejected (403), own-account regenerate/revoke both correct.
- **Outbound webhooks** (since 2026-09-12): one URL per `app_source`, HMAC-SHA256-signed (`X-CGC-Signature`), delivered from inside `/governance/decision` itself with a 5s timeout — verified live with a real local HTTP receiver (signature matched byte-for-byte). No retry queue, honestly disclosed, not silently assumed reliable.
- **A real usage panel** (since 2026-09-12): `/tenants/my-apps` now returns `decisions_used`/`decisions_quota` per app, backed by a NEW counter namespaced `app_source:<name>` inside `cgc_guard.tenant_usage` — deliberately separate from the org_id-keyed quota-enforcement counters `check_quota`/`reserve_quota` already used, so this is purely additive and can't affect real rate-limiting.
- **Key-rotation advance notice, not forced rotation** (since 2026-09-12): `/tenants/my-apps` flags any active key ≥90 days old (`rotation_recommended`), shown in the dashboard; `POST /admin/keys/rotation-check` (cron-callable) Slack-alerts an operator about the same. Deliberately does NOT auto-rotate anything — there's no per-customer notification channel yet, so silently swapping a live key on a timer could break production traffic with no way to warn the holder first.
- **A real, hand-written integration guide** (`GET /docs/getting-started`, since 2026-09-12) — signup → self-signup → first decision → webhook signature verification → rate limits, with real curl examples against the actual live endpoints above. The auto-generated Swagger at `/docs` documents every field; this explains the flow.
