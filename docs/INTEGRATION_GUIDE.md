# CGC Core — External Integration Guide

**Grounded in a direct code audit (2026-09-14), not aspirational.** Every claim
below was verified against the actual implementation. Where the real behavior
falls short of what you'd expect from a mature integration platform, that's
called out explicitly rather than glossed over — that honesty is itself part
of what this document is for: helping a prospective integrating company (or
one of our own products) make an accurate go/no-go call, not a sales pitch.

## 1. What CGC Core is (and isn't)

CGC Core is an AI-governance decision engine: a consuming application sends
it a proposed AI-driven action, CGC Core runs that action through four
independent scoring modules (pattern/entity analysis, ethical calibration,
predictive risk, strategic advisory), aggregates them into an approve/reject
decision, checks it against EU AI Act / NIST RMF / GLBA Safeguards Rule
requirements, cryptographically seals the decision (RSA-PSS signature +
hash-chained audit ledger), and returns a verdict with a correlation ID your
system can use for later audit lookup.

**It is not**: a general-purpose API gateway, a no-code workflow tool, or a
certified/audited product — there is no independent security or cryptography
audit yet, and as of this writing, 100% of production traffic is the
operator's own products. If your company needs "SOC 2 report on file" as a
procurement gate, CGC Core cannot clear that today.

## 2. Prerequisites before you integrate

- An email address to register an account with (`POST /auth/signup`).
- A unique, URL-safe slug for your application (`^[a-z][a-z0-9-]{2,49}$`,
  lowercase, hyphens allowed) — this becomes your permanent `app_source`
  identifier and cannot collide with an existing one or a reserved name.
- A willingness to accept the current gaps in Section 8 before going live
  with anything regulator-facing or handling real user data through the
  decision pipeline.

## 3. Onboarding flow (as it actually works today)

1. `POST /auth/signup` — email + password. Rate-limited 5/hour/IP. You get a
   plain `user` role account (role can't be elevated from this endpoint by
   design — see Section 7.3).
2. `POST /auth/signin` — returns a 30-day HS256 JWT.
3. `POST /tenants/self-signup` with `{"app_source": "your-app-slug"}`,
   authenticated with that JWT. Rate-limited 3/hour/account. Returns:
   - A live API key, prefixed `cgc_live_...` — **shown once, store it
     immediately**, only its SHA-256 hash is kept server-side.
   - A FREE-tier billing record for your `app_source`, created in the same
     call.
4. `GET /tenants/my-apps` — lists everything you (as the account that created
   it) own. Ownership is scoped by creator email, not by organization.
5. You're ready to call `/governance/decision` (Section 5).

Key rotation and revocation, when you need them:
`POST /tenants/my-apps/{app_source}/keys/regenerate` and
`.../keys/{key_id}/revoke` — both ownership-checked against your account.

## 4. Authentication — three mechanisms, one you should actually use

| Mechanism | How | Tenant binding | Use for |
|---|---|---|---|
| Per-tenant API key (`cgc_live_...`) | `Authorization: Bearer cgc_live_...` | Cryptographically bound to your `app_source` at issuance — you cannot spoof a different app_source with someone else's key | **This one.** The real, current integration path. |
| Legacy shared service key | `CGC_SERVICE_API_KEY` env-configured on the CGC Core side | None — resolves to `role: service`, `app_source: None`; the caller's declared `app_source` is only checked against a static allowlist | Internal/operator use only. Don't build a new external integration on this. |
| Session JWT | Signin/SSO (Google OIDC, admin-provisioned SAML) | Per-user session | Your own team members using the CGC Core dashboard directly, not machine-to-machine integration. |

## 5. Making your first governance decision call

```
POST /governance/decision
Authorization: Bearer cgc_live_...
Content-Type: application/x-www-form-urlencoded

org_id=your-org-id
&action=describe_the_ai_action
&input_data={"json": "payload as a string"}
&user_email=end.user@example.com
&data_domains=["financial","health"]
&app_source=your-app-slug
&area=lending
```

Response:

```json
{
  "approved": true,
  "outcome": "APPROVE",
  "reason": "...",
  "correlation_id": "...",
  "prefilter": { "...": "..." },
  "decision": { "...": "..." },
  "total_latency_ms": 240,
  "decision_id": "..."
}
```

Note the request body is form-encoded, not JSON, and `input_data` /
`data_domains` are JSON-encoded *strings within* the form body — an easy
first-integration mistake. A Python SDK (`sdk/python/`, package
`cgc-core-sdk`) handles this encoding for you — see its own README for
install/usage; it's the fastest path in for a Python caller. No SDK exists
yet for other languages, so this shape still has to be hand-built with
your HTTP client there. Full interactive schema: `GET /docs` (Swagger). A
hand-written walkthrough also lives at `GET /docs/getting-started`.

## 6. Webhooks

`GET` / `POST` / `DELETE /tenants/my-apps/{app_source}/webhook` — one URL per
app. Deliveries are HMAC-SHA256 signed (`X-CGC-Signature: sha256=<hex>`),
sent synchronously inside the `/governance/decision` request with a 5-second
timeout. **There is no retry queue** — if your endpoint is briefly down when
a decision fires, that notification is gone for good. Design your consumer
to also poll `GET /tenants/my-apps/{app_source}/decisions` as a fallback if
a missed webhook would be a real problem for you.

## 7. What you're actually trusting — the honest multi-tenancy picture

This is the part most integration docs gloss over. CGC Core enforces tenant
isolation at **two different strengths depending on the table**, and it
matters for what you should assume is safe:

**7.1 — Database-enforced (strong)**: `cgc_pod.*` and most of `cgc_guard.*`
use real Postgres row-level security, scoped via a `cgc_app` role and
`current_setting('cgc.current_tenant_id')` set per-connection. This is
verified by tests that connect *as* the RLS-restricted role specifically
(not the bypass-RLS admin role) — genuine defense in depth, not just
"the application code remembers to filter."

**7.2 — Application-code-enforced only (weaker), confirmed 2026-09-14**:
`cgc_tco.audit_trail` — **the actual decision history you'd query as an
integrating company** — is scoped only by a `WHERE app_source = %s` filter
in Python, executed over an unrestricted admin database connection. There's
no database-level backstop if that filter is ever omitted in a future code
change. A live-DB check confirmed this is the right call, not just the
current state: a leftover `tenant_id`-based RLS policy on this table was
found and dropped after verifying `tenant_id` doesn't actually correspond
to a real per-tenant identifier for at least one app (`ledgiproof`'s rows
carry ad-hoc testing strings in that column, not a consistent tenant ID) —
so DB-level RLS here wouldn't have isolated data correctly even if it had
been active. This is the one place where "is my data isolated from other
tenants" has a real, not theoretical, answer of "yes, today, because the
code is careful — not because the database won't let it happen otherwise."

**7.3 — Credential-level binding**: your API key is cryptographically tied
to your `app_source` at issuance (fixed after a real historical bug where a
client-declared `app_source` field was trusted at face value on
unauthenticated signup — see the CGC Core security audit for the full
history). You cannot use a valid key to act as a different tenant.

If your company's compliance posture requires DB-enforced isolation on
*every* table touching your data, ask specifically about 7.2 before relying
on this for anything regulator-sensitive.

## 8. Known limitations — read before committing to a launch date

1. **No SDK outside Python.** A Python SDK exists (`sdk/python/`,
   `cgc-core-sdk`) — every other language is still raw HTTP, form-encoded,
   by hand.
2. **No real API versioning** beyond a single `/api/v1` path — no
   deprecation policy exists yet for breaking changes.
3. **Audit-trail isolation is app-code-only**, not DB-enforced (Section 7.2).
4. **Webhook retries are best-effort, not guaranteed.** A failed delivery
   is queued and retried on a 5-tier backoff (5m/15m/1h/4h/24h, 5 attempts
   max — see `POST /admin/webhooks/process-retries`, run every 10 minutes
   by a GitHub Actions cron), then given up on. There's still no dead-letter
   surface for permanently-failed deliveries beyond that log line.
5. **SAML SSO is admin-provisioned only** — not self-service. If your
   enterprise customers expect to configure their own Okta/Azure AD
   connection, that's a manual request to the CGC Core operator today.
6. **The decision-scoring weight matrix is API-configurable per tenant**
   (`GET/PUT/DELETE /tenants/my-apps/{app_source}/weighting/{area}/{level}`)
   as of 2026-09-14 — you're no longer stuck asking the operator to edit
   source and redeploy for a weight change. Falls back to the global
   default matrix (still source-only) when no override is set.
7. **No independent security or cryptography audit has been performed.**
   The crypto choices read as sound on direct code review (RSA-PSS-SHA256,
   Fernet/AES, bcrypt, no homegrown primitives) but "looks correct on
   review" is not the same claim as "audited."
8. **Zero external paying customers as of this writing.** Every byte of
   production traffic today is the operator's own products. You would be
   the first real external integration, not the hundredth.
9. **Per-plan rate limits exist internally but aren't published as a
   documented SLA** — you can hit undocumented 429s in production before
   knowing your actual ceiling.

## 9. A suitability checklist, before you integrate

Ask these before committing:

- [ ] Can my product tolerate "app-code-enforced" isolation for decision
      history (7.2), or do I need DB-level guarantees on every table?
- [ ] Is best-effort webhook retry (5 attempts over 24h, then dropped) good
      enough, or do I need my own reconciliation/polling fallback too?
- [ ] Is a hand-built HTTP integration acceptable if my stack isn't Python
      (no SDK exists yet outside `sdk/python/`)?
- [ ] Do I need a documented, contractual rate-limit SLA before launch, or
      is "ask the operator" acceptable?
- [ ] Does my own compliance/procurement process require a third-party
      security audit of anything I integrate with? (CGC Core doesn't have
      one yet.)
- [ ] Am I comfortable being an early/first external integration, including
      the higher likelihood of rough edges that only show up under real
      third-party load?

If most of these are "yes, acceptable," CGC Core's actual (not aspirational)
integration surface is real and functional. If several are hard blockers,
that's a genuine reason to wait rather than integrate today.

---

*This document reflects a direct audit of the codebase at
`C:\Users\soler\Desktop\cgc_core` on 2026-09-14. It will drift out of date as
the code changes — re-verify against source before relying on it for a
launch decision more than a few weeks out.*
