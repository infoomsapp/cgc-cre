# cgc-core-sdk (TypeScript/JavaScript)

TypeScript/JavaScript client for [CGC Core](https://github.com/infoomsapp/cgc-cre),
Olympus Mont's AI governance engine. Mirrors
[`sdk/python/cgc_core_sdk`](../python/README.md)'s method list and behavior
1:1 -- same coverage, same call shapes, just idiomatic camelCase and
`async`/`await` instead of snake_case. Uses the global `fetch` (Node 18+,
every evergreen browser) -- no runtime HTTP dependency.

## Install

From this directory:

```bash
npm install
npm run build
```

Or point at the checkout directly in another project's `package.json`:
`"cgc-core-sdk": "file:../path/to/cgc_core/sdk/js"`.

## Quickstart

```typescript
import { CGCCoreClient } from "cgc-core-sdk";

const client = new CGCCoreClient(); // defaults to https://cgc-cre.vercel.app

// One-time onboarding: create an account, claim your app_source, get a key.
await client.login("you@example.com", "a strong password");
const issued = await client.claimAppSource("my-product");
const apiKey = issued.key; // store this -- it's shown in full only once

// Day-to-day: authenticate with the long-lived API key instead of login().
const prod = new CGCCoreClient({ token: apiKey });

const result = await prod.submitDecision({
  orgId: "acme-corp",
  action: "loan_application_review",
  inputData: { applicantIncome: 85000, requestedAmount: 15000 },
  userEmail: "analyst@acme-corp.com",
  dataDomains: ["financial"],
  appSource: "my-product",
});
console.log(result.decision, result.decision_id);
```

## Error handling

Every non-2xx response throws `CGCCoreAPIError` (401/403 throw the more
specific `CGCCoreAuthError`, a subclass), carrying `statusCode` and
`detail` matching the API's own `{"detail": "..."}` error body:

```typescript
import { CGCCoreClient, CGCCoreAPIError } from "cgc-core-sdk";

try {
  await client.submitDecision(/* ... */);
} catch (e) {
  if (e instanceof CGCCoreAPIError) {
    console.log(e.statusCode, e.detail);
  }
}
```

## What's covered

- **Auth**: `signup`, `signin`, `login`, `setToken`
- **Onboarding**: `claimAppSource`, `listMyApps`, `regenerateKey`, `revokeKey`
- **Governance**: `submitDecision`, `getReportPdf`, `getTimeseries`, `getScoringMethodology`
- **Monitoring**: `reportError`, `listErrors`, `errorStats`, `resolveError`, `deleteError`, `bulkDeleteErrors`
- **Launch readiness**: `getLaunchSummary`, `listChecklist`, `upsertChecklistItem`, `deleteChecklistItem`, `reportLaunchError`, `listLaunchErrors`, `resolveLaunchError`, `refreshLaunchReadiness`
- **Webhooks**: `getWebhook`, `setWebhook`, `deleteWebhook`
- **Weighting overrides**: `getWeighting`, `setWeighting`, `deleteWeighting`
- **`health()`** (unauthenticated)

Not covered: platform-admin-only endpoints (`/admin/users`, `/admin/cleanup/*`,
key-rotation checks, SAML connection management, billing checkout/portal
links) -- those aren't things an integrating tenant calls itself.

## Auth model

Every authenticated endpoint takes the same `Authorization: Bearer <token>`
header, where `<token>` is either a signin JWT (30-day expiry) or a
long-lived API key. There's no separate "API key mode" -- `CGCCoreClient`
just stores whichever token you give it and sends it the same way on every
call.

## Development

```bash
npm test   # builds (tsc) then runs the suite against dist/ via node:test
```
