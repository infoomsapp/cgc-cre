// Unit tests for CGCCoreClient -- mocks the global fetch, no live server
// or database needed. Verifies request shaping (headers, form vs. JSON
// encoding, query params) and error mapping against dist/ (the compiled
// output consumers actually get), not server behavior.

import { test } from "node:test";
import assert from "node:assert/strict";
import { CGCCoreClient, CGCCoreAPIError, CGCCoreAuthError } from "../dist/index.js";

const BASE = "https://cgc-cre.example.test";

function fakeFetch(handler) {
  return async (url, init) => handler(new URL(url), init);
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

test("signin stores the token on the client", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    fetchImpl: fakeFetch(async (url) => {
      assert.equal(url.pathname, "/auth/signin");
      return jsonResponse(200, { access_token: "jwt-xyz", token_type: "bearer", user: { email: "a@b.com" } });
    }),
  });
  const result = await client.signin("a@b.com", "pw");
  assert.equal(client.token, "jwt-xyz");
  assert.equal(result.user.email, "a@b.com");
});

test("submitDecision form-encodes input_data/data_domains as JSON strings", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    token: "tok_abc123",
    fetchImpl: fakeFetch(async (url, init) => {
      assert.equal(url.pathname, "/governance/decision");
      assert.equal(init.headers["Content-Type"], "application/x-www-form-urlencoded");
      const params = new URLSearchParams(init.body);
      assert.deepEqual(JSON.parse(params.get("input_data")), { amount: 100 });
      assert.deepEqual(JSON.parse(params.get("data_domains")), ["financial"]);
      assert.equal(params.get("org_id"), "acme");
      return jsonResponse(200, { decision: "ALLOW", decision_id: "dec_1" });
    }),
  });
  const result = await client.submitDecision({
    orgId: "acme",
    action: "review",
    inputData: { amount: 100 },
    userEmail: "u@acme.com",
    dataDomains: ["financial"],
    appSource: "acme-app",
  });
  assert.equal(result.decision, "ALLOW");
});

test("sends the Authorization header on authenticated calls", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    token: "tok_abc123",
    fetchImpl: fakeFetch(async (url, init) => {
      assert.equal(init.headers["Authorization"], "Bearer tok_abc123");
      return jsonResponse(200, { apps: [] });
    }),
  });
  await client.listMyApps();
});

test("401 raises CGCCoreAuthError with status and detail", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    token: "tok_abc123",
    fetchImpl: fakeFetch(async () => jsonResponse(401, { detail: "Invalid token" })),
  });
  await assert.rejects(
    () => client.listMyApps(),
    (err) => {
      assert.ok(err instanceof CGCCoreAuthError);
      assert.equal(err.statusCode, 401);
      assert.equal(err.detail, "Invalid token");
      return true;
    },
  );
});

test("400 raises CGCCoreAPIError but NOT CGCCoreAuthError", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    token: "tok_abc123",
    fetchImpl: fakeFetch(async () => jsonResponse(400, { detail: "ecm_weight must be between 0.0 and 1.0" })),
  });
  await assert.rejects(
    () =>
      client.setWeighting("acme", "DEFAULT", "LOW", {
        ecmWeight: 1.5,
        pfmWeight: 0.2,
        panWeight: 0.2,
        sdaWeight: 0.1,
        approvalThreshold: 0.5,
      }),
    (err) => {
      assert.ok(err instanceof CGCCoreAPIError);
      assert.ok(!(err instanceof CGCCoreAuthError));
      assert.equal(err.statusCode, 400);
      return true;
    },
  );
});

test("health() works without a token", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    fetchImpl: fakeFetch(async (url, init) => {
      assert.equal(init.headers["Authorization"], undefined);
      return jsonResponse(200, { status: "ok" });
    }),
  });
  const result = await client.health();
  assert.deepEqual(result, { status: "ok" });
});

test("listErrors sends the real query params (app_source, resolved, since_days, limit)", async () => {
  const client = new CGCCoreClient({
    baseUrl: BASE,
    token: "tok_abc123",
    fetchImpl: fakeFetch(async (url) => {
      assert.equal(url.searchParams.get("app_source"), "acme");
      assert.equal(url.searchParams.get("resolved"), "false");
      assert.equal(url.searchParams.get("limit"), "50");
      return jsonResponse(200, { total: 0, reports: [] });
    }),
  });
  await client.listErrors({ appSource: "acme", resolved: false, limit: 50 });
});

test("getReportPdf returns raw bytes, not parsed JSON", async () => {
  const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // "%PDF"
  const client = new CGCCoreClient({
    baseUrl: BASE,
    token: "tok_abc123",
    fetchImpl: fakeFetch(async (url) => {
      assert.equal(url.pathname, "/governance/reports/acme");
      return new Response(pdfBytes, { status: 200, headers: { "Content-Type": "application/pdf" } });
    }),
  });
  const buf = await client.getReportPdf("acme");
  assert.deepEqual(new Uint8Array(buf), pdfBytes);
});
