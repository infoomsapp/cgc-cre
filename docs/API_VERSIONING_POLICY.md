# CGC Core API versioning policy

## Current reality (read this first)

`root_path="/api/v1"` is set on the FastAPI app (`app/main.py`) for one
reason only: correct OpenAPI/Swagger URLs when the app runs behind a
reverse proxy. It does **not** put `/api/v1` in any route's real path —
`GET /health` is `GET /health`, not `GET /api/v1/health`, confirmed live.
There is currently exactly one API surface, unversioned in practice
despite the name. This document is the policy for what happens *when*
that changes, not a claim that versioning already exists today.

The app does carry a version string (`version="2.2.2"` in the same
`FastAPI(...)` call) — that's release tracking for the whole service
(bumped per meaningful deploy), not an API contract version. The two are
allowed to diverge; don't conflate them.

## Compatibility guarantees, starting now

While there is one unversioned surface, these commitments apply to every
endpoint in this codebase, enforced the same way any other regression
would be — via review, not tooling:

**Non-breaking (ship anytime, no notice needed):**
- Adding a new endpoint.
- Adding a new optional field to a request body (with a default) or a
  new field to a response body.
- Adding a new enum value to a field that's documented as open-ended.
- Loosening a validation constraint (e.g. raising a length cap).
- New optional query parameters.

**Breaking (needs the process in "Introducing a breaking change" below):**
- Removing or renaming an endpoint, field, or query parameter.
- Changing a field's type or semantics (e.g. a timestamp format, an enum
  becoming case-sensitive).
- Making an optional request field required.
- Narrowing a validation constraint in a way that rejects previously-valid
  requests.
- Changing default behavior a caller could reasonably have depended on
  (e.g. the webhook retry backoff schedule, rate-limit ceilings tenants
  are told about).
- Tightening auth/authorization on an existing endpoint (this is a
  security fix, not a "breaking change" in the deprecation sense — it
  still needs advance notice where feasible, per the incident-response
  judgment call at the time, but doesn't wait for a deprecation window).

## Introducing a breaking change

1. The new behavior ships at a real, distinct path prefix — `/v2/...` —
   introduced as its own `APIRouter`/sub-app, mounted alongside the
   existing routes. `root_path` stays cosmetic; this is a real path
   segment, not another no-op prefix.
2. The old surface (implicitly "v1" today) keeps working, unmodified,
   for a minimum deprecation window of **90 days** from the day `/v2` for
   that specific endpoint ships.
3. Every response from a deprecated endpoint gains a `Deprecation` header
   (RFC 8594) once its replacement exists, naming the sunset date.
4. Known integrators (anyone who has called `/tenants/self-signup` — the
   `cgc_admin_notifications` / webhook config on file for their
   `app_source`, once one exists, is the notification channel; until
   then, direct email to whatever address they signed up with) get a
   heads-up before the 90-day clock starts, not partway through it.
5. After the window, the deprecated version is removed in its own commit
   with its own changelog entry — never silently, never bundled with
   unrelated changes.

## What this policy deliberately does not promise

- **No LTS tier.** One deprecation window, not a menu of support tiers —
  this is a single-team-maintained service, not a platform with the
  staffing for parallel long-term-support branches.
- **No SemVer-per-request negotiation** (`Accept-Version` headers, content
  negotiation). Path-based versioning (`/v2/...`) was chosen over that
  because it's debuggable from a URL alone — a caller, an on-call
  engineer, or this document itself can look at a request and know
  immediately which contract applies, no header inspection required.
- **No commitment on the /docs/getting-started walkthrough or dashboard
  HTML staying stable** — those are internal-facing, not part of the API
  contract this document covers.

## Status as of 2026-09-14

No breaking change has been proposed yet, so there is no `/v2` prefix to
point to — this document exists so that *when* one is needed, the process
is already agreed rather than improvised under deadline pressure. See
[INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) Section 8 for how this policy
is reflected in the current list of known limitations.
