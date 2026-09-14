# cgc-core-sdk

Python client for [CGC Core](https://github.com/infoomsapp/cgc-cre), Olympus
Mont's AI governance engine. Wraps the self-service integration surface
described in [`docs/INTEGRATION_GUIDE.md`](../../docs/INTEGRATION_GUIDE.md):
account signup, claiming an `app_source` and getting an API key, submitting
governed decisions, application-error monitoring, launch-readiness tracking,
webhook configuration, and per-tenant scoring-weight overrides.

## Install

From this directory:

```bash
pip install .
```

Or point at the checkout directly: `pip install /path/to/cgc_core/sdk/python`.

## Quickstart

```python
from cgc_core_sdk import CGCCoreClient

client = CGCCoreClient()  # defaults to https://cgc-cre.vercel.app

# One-time onboarding: create an account, claim your app_source, get a key.
client.login("you@example.com", "a strong password")
issued = client.claim_app_source("my-product")
api_key = issued["key"]  # store this -- it's shown in full only once

# Day-to-day: authenticate with the long-lived API key instead of signin().
client = CGCCoreClient(token=api_key)

result = client.submit_decision(
    org_id="acme-corp",
    action="loan_application_review",
    input_data={"applicant_income": 85000, "requested_amount": 15000},
    user_email="analyst@acme-corp.com",
    data_domains=["financial"],
    app_source="my-product",
)
print(result["decision"], result["decision_id"])
```

## Error handling

Every non-2xx response raises `CGCCoreAPIError` (401/403 raise the more
specific `CGCCoreAuthError`, a subclass), carrying `status_code` and
`detail` matching the API's own `{"detail": "..."}` error body:

```python
from cgc_core_sdk import CGCCoreClient, CGCCoreAPIError

try:
    client.submit_decision(...)
except CGCCoreAPIError as e:
    print(e.status_code, e.detail)
```

## What's covered

- **Auth**: `signup`, `signin`, `login`, `set_token`
- **Onboarding**: `claim_app_source`, `list_my_apps`, `regenerate_key`, `revoke_key`
- **Governance**: `submit_decision`, `get_report_pdf`, `get_timeseries`, `get_scoring_methodology`
- **Monitoring**: `report_error`, `list_errors`, `error_stats`, `resolve_error`, `delete_error`, `bulk_delete_errors`
- **Launch readiness**: `get_launch_summary`, `list_checklist`, `upsert_checklist_item`, `delete_checklist_item`, `report_launch_error`, `list_launch_errors`, `resolve_launch_error`, `refresh_launch_readiness`
- **Webhooks**: `get_webhook`, `set_webhook`, `delete_webhook`
- **Weighting overrides**: `get_weighting`, `set_weighting`, `delete_weighting`
- **`health()`** (unauthenticated)

Not covered: platform-admin-only endpoints (`/admin/users`, `/admin/cleanup/*`,
key-rotation checks, SAML connection management, billing checkout/portal
links) -- those aren't things an integrating tenant calls itself.

**Known API limitation**: `get_report_pdf` and `get_timeseries` check a
static allowlist server-side, not tenant ownership -- they work for the
first-party apps CGC Core already governs, but a freshly self-signed-up
`app_source` (via `claim_app_source`) will get a 400 from those two calls
until that's fixed server-side. Every other method works for self-signup
tenants today.

## Auth model

Every authenticated endpoint takes the same `Authorization: Bearer <token>`
header, where `<token>` is either a signin JWT (30-day expiry) or a
long-lived API key. There's no separate "API key mode" -- `CGCCoreClient`
just stores whichever token you give it and sends it the same way on every
call.
