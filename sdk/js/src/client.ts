/**
 * TypeScript/JavaScript client for CGC Core
 * (https://github.com/infoomsapp/cgc-cre).
 *
 * Covers the self-service integration surface documented in
 * docs/INTEGRATION_GUIDE.md: account signup/login, claiming an app_source
 * and getting an API key, submitting governance decisions, reading back
 * reports/timeseries, application-error monitoring, launch-readiness
 * tracking, webhook configuration, and per-tenant scoring-weight
 * overrides. Mirrors sdk/python/cgc_core_sdk's method list and behavior
 * 1:1 -- see that package if you need to cross-check a call shape.
 *
 * Every authenticated endpoint on this API takes the same single
 * credential -- an `Authorization: Bearer <token>` header, where <token>
 * is either a signin JWT (30-day expiry) or a long-lived API key issued
 * via self-signup or key regeneration. This client stores whichever one
 * you give it and sends it the same way on every request; there is no
 * separate "API key mode" vs "session mode".
 *
 * Not covered here: platform-admin-only endpoints (/admin/users,
 * /admin/cleanup/*, /admin/keys/rotation-check, SAML connection
 * management, billing checkout/portal links) -- those aren't things an
 * integrating tenant calls themselves.
 *
 * Uses the global `fetch` (Node 18+, every evergreen browser) -- no
 * runtime HTTP dependency.
 */

import { CGCCoreAPIError, CGCCoreAuthError } from "./errors.js";

export const DEFAULT_BASE_URL = "https://cgc-cre.vercel.app";
const DEFAULT_TIMEOUT_MS = 30_000;

export interface CGCCoreClientOptions {
  baseUrl?: string;
  token?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface SubmitDecisionInput {
  orgId: string;
  action: string;
  inputData: Record<string, unknown>;
  userEmail: string;
  dataDomains: string[];
  appSource?: string;
  area?: string;
}

export interface SetWeightingInput {
  ecmWeight: number;
  pfmWeight: number;
  panWeight: number;
  sdaWeight: number;
  approvalThreshold: number;
  criticalFrameworkEnforcement?: boolean;
  requireHumanReview?: boolean;
}

export interface ReportErrorInput {
  appSource: string;
  message: string;
  environment?: string;
  severity?: string;
  stack?: string;
  url?: string;
  userAgent?: string;
  context?: Record<string, unknown>;
}

export interface ReportLaunchErrorInput {
  source: string;
  message: string;
  severity?: string;
  detail?: Record<string, unknown>;
}

export interface UpsertChecklistItemInput {
  category: string;
  item: string;
  status?: string;
  note?: string;
  itemId?: number;
}

// biome-ignore lint: intentionally loose -- response shapes are the
// server's, not re-declared here to avoid drifting out of sync with it.
export type JSONValue = any;

export class CGCCoreClient {
  baseUrl: string;
  token?: string;
  private timeoutMs: number;
  private fetchImpl: typeof fetch;

  constructor(options: CGCCoreClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  setToken(token: string): void {
    this.token = token;
  }

  // ------------------------------------------------------------------
  // internals
  // ------------------------------------------------------------------

  private async request(
    method: string,
    path: string,
    opts: {
      jsonBody?: Record<string, unknown>;
      formData?: Record<string, string>;
      params?: Record<string, string | number | boolean | undefined>;
      raw?: boolean;
    } = {},
  ): Promise<JSONValue> {
    const url = new URL(`${this.baseUrl}${path}`);
    if (opts.params) {
      for (const [k, v] of Object.entries(opts.params)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }

    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    let body: string | undefined;
    if (opts.jsonBody !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.jsonBody);
    } else if (opts.formData !== undefined) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(opts.formData).toString();
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await this.fetchImpl(url.toString(), {
        method,
        headers,
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!resp.ok) {
      const text = await resp.text();
      let detail: unknown = text;
      try {
        const parsed = JSON.parse(text);
        detail = parsed?.detail ?? text;
      } catch {
        // not JSON -- keep raw text as detail
      }
      const ErrorClass = resp.status === 401 || resp.status === 403 ? CGCCoreAuthError : CGCCoreAPIError;
      throw new ErrorClass(resp.status, detail, text);
    }

    if (opts.raw) return resp;

    const text = await resp.text();
    if (!text) return null;
    return JSON.parse(text);
  }

  // ------------------------------------------------------------------
  // auth
  // ------------------------------------------------------------------

  /** Create a plain user account (does not sign you in -- call signin()
   * after, or use login() to do both). */
  async signup(email: string, password: string): Promise<JSONValue> {
    return this.request("POST", "/auth/signup", { jsonBody: { email, password } });
  }

  /** Authenticate and store the returned JWT on this client for
   * subsequent calls. Returns the full {access_token, token_type, user}
   * response. */
  async signin(email: string, password: string): Promise<JSONValue> {
    const result = await this.request("POST", "/auth/signin", { jsonBody: { email, password } });
    this.token = result.access_token;
    return result;
  }

  /** signup() then signin() in one call, ignoring a 409 if the account
   * already exists -- the common case for a script that just wants to
   * end up authenticated. */
  async login(email: string, password: string): Promise<JSONValue> {
    try {
      await this.signup(email, password);
    } catch (e) {
      if (!(e instanceof CGCCoreAPIError) || e.statusCode !== 409) throw e;
    }
    return this.signin(email, password);
  }

  // ------------------------------------------------------------------
  // tenant onboarding / API keys (requires a signed-in user token)
  // ------------------------------------------------------------------

  /** Claim a new app_source and receive its first API key. Requires an
   * authenticated user token (from signin()/login()), NOT an existing API
   * key. The returned key is shown in full only this once -- store it
   * now. */
  async claimAppSource(appSource: string): Promise<JSONValue> {
    return this.request("POST", "/tenants/self-signup", { jsonBody: { app_source: appSource } });
  }

  async listMyApps(): Promise<JSONValue[]> {
    const result = await this.request("GET", "/tenants/my-apps");
    return result.apps;
  }

  /** Revokes every active key you hold for appSource and issues a fresh
   * one. */
  async regenerateKey(appSource: string): Promise<JSONValue> {
    return this.request("POST", `/tenants/my-apps/${encodeURIComponent(appSource)}/keys/regenerate`);
  }

  async revokeKey(appSource: string, keyId: string): Promise<JSONValue> {
    return this.request(
      "POST",
      `/tenants/my-apps/${encodeURIComponent(appSource)}/keys/${encodeURIComponent(keyId)}/revoke`,
    );
  }

  // ------------------------------------------------------------------
  // governance -- the core product
  // ------------------------------------------------------------------

  /** Run one input through the governance pipeline. POST /governance/
   * decision is form-encoded (not JSON) on the server side --
   * input_data and data_domains are sent as JSON-encoded strings inside
   * form fields; this method does that encoding for you. */
  async submitDecision(input: SubmitDecisionInput): Promise<JSONValue> {
    return this.request("POST", "/governance/decision", {
      formData: {
        org_id: input.orgId,
        action: input.action,
        input_data: JSON.stringify(input.inputData),
        user_email: input.userEmail,
        data_domains: JSON.stringify(input.dataDomains),
        app_source: input.appSource ?? "unknown",
        area: input.area ?? "DEFAULT",
      },
    });
  }

  /** Returns the raw PDF bytes for a per-app governance report.
   * fromDate/toDate are ISO date strings (YYYY-MM-DD); defaults to the
   * trailing 30 days. Works for any app_source you own (claimed via
   * claimAppSource()) or a first-party one. */
  async getReportPdf(appSource: string, fromDate?: string, toDate?: string): Promise<ArrayBuffer> {
    const resp: Response = await this.request("GET", `/governance/reports/${encodeURIComponent(appSource)}`, {
      params: { from_date: fromDate, to_date: toDate },
      raw: true,
    });
    return resp.arrayBuffer();
  }

  async getTimeseries(appSource: string, hours = 24): Promise<JSONValue> {
    return this.request("GET", `/governance/timeseries/${encodeURIComponent(appSource)}`, { params: { hours } });
  }

  async getScoringMethodology(): Promise<JSONValue> {
    return this.request("GET", "/governance/scoring-methodology");
  }

  // ------------------------------------------------------------------
  // application error monitoring (crash/exception telemetry)
  // ------------------------------------------------------------------

  async reportError(input: ReportErrorInput): Promise<JSONValue> {
    return this.request("POST", "/monitor/error", {
      jsonBody: {
        app_source: input.appSource,
        environment: input.environment ?? "production",
        severity: input.severity ?? "error",
        message: input.message,
        stack: input.stack,
        url: input.url,
        user_agent: input.userAgent,
        context: input.context,
      },
    });
  }

  async listErrors(opts: {
    appSource?: string;
    resolved?: boolean;
    sinceDays?: number;
    limit?: number;
  } = {}): Promise<JSONValue> {
    return this.request("GET", "/monitor/errors", {
      params: {
        app_source: opts.appSource,
        resolved: opts.resolved,
        since_days: opts.sinceDays,
        limit: opts.limit ?? 100,
      },
    });
  }

  async errorStats(days = 7): Promise<JSONValue> {
    return this.request("GET", "/monitor/errors/stats", { params: { days } });
  }

  async resolveError(fingerprint: string): Promise<JSONValue> {
    return this.request("POST", `/monitor/errors/${encodeURIComponent(fingerprint)}/resolve`);
  }

  async deleteError(fingerprint: string): Promise<JSONValue> {
    return this.request("DELETE", `/monitor/errors/${encodeURIComponent(fingerprint)}`);
  }

  async bulkDeleteErrors(fingerprints: string[]): Promise<JSONValue> {
    return this.request("POST", "/monitor/errors/bulk-delete", { jsonBody: { fingerprints } });
  }

  // ------------------------------------------------------------------
  // launch readiness (store submission tracking, incl. process errors)
  // ------------------------------------------------------------------

  async getLaunchSummary(appSource: string): Promise<JSONValue> {
    return this.request("GET", `/launch-readiness/${encodeURIComponent(appSource)}/summary`);
  }

  async listChecklist(appSource: string): Promise<JSONValue[]> {
    const result = await this.request("GET", `/launch-readiness/${encodeURIComponent(appSource)}/checklist`);
    return result.items;
  }

  async upsertChecklistItem(appSource: string, input: UpsertChecklistItemInput): Promise<JSONValue> {
    return this.request("POST", `/launch-readiness/${encodeURIComponent(appSource)}/checklist`, {
      jsonBody: {
        id: input.itemId,
        category: input.category,
        item: input.item,
        status: input.status ?? "pending",
        note: input.note,
      },
    });
  }

  async deleteChecklistItem(appSource: string, itemId: number): Promise<JSONValue> {
    return this.request(
      "DELETE",
      `/launch-readiness/${encodeURIComponent(appSource)}/checklist/${itemId}`,
    );
  }

  /** Log a launch/submission-process error (a store rejection, a signing
   * failure, a failed CI build) -- distinct from reportError(), which is
   * runtime app telemetry, not the launch process itself. */
  async reportLaunchError(appSource: string, input: ReportLaunchErrorInput): Promise<JSONValue> {
    return this.request("POST", `/launch-readiness/${encodeURIComponent(appSource)}/errors`, {
      jsonBody: {
        source: input.source,
        severity: input.severity ?? "error",
        message: input.message,
        detail: input.detail,
      },
    });
  }

  async listLaunchErrors(appSource: string, status?: string): Promise<JSONValue[]> {
    const result = await this.request("GET", `/launch-readiness/${encodeURIComponent(appSource)}/errors`, {
      params: { status },
    });
    return result.errors;
  }

  async resolveLaunchError(appSource: string, errorId: number): Promise<JSONValue> {
    return this.request(
      "POST",
      `/launch-readiness/${encodeURIComponent(appSource)}/errors/${errorId}/resolve`,
    );
  }

  async refreshLaunchReadiness(appSource: string): Promise<JSONValue> {
    return this.request("POST", `/launch-readiness/${encodeURIComponent(appSource)}/refresh`);
  }

  // ------------------------------------------------------------------
  // webhooks
  // ------------------------------------------------------------------

  async getWebhook(appSource: string): Promise<JSONValue> {
    return this.request("GET", `/tenants/my-apps/${encodeURIComponent(appSource)}/webhook`);
  }

  /** Returns the signing secret in full -- shown only this once, store
   * it. CGC Core signs every delivery with HMAC-SHA256 over the JSON
   * body as `X-CGC-Signature: sha256=<hex>`. */
  async setWebhook(appSource: string, url: string): Promise<JSONValue> {
    return this.request("POST", `/tenants/my-apps/${encodeURIComponent(appSource)}/webhook`, {
      jsonBody: { url },
    });
  }

  async deleteWebhook(appSource: string): Promise<JSONValue> {
    return this.request("DELETE", `/tenants/my-apps/${encodeURIComponent(appSource)}/webhook`);
  }

  // ------------------------------------------------------------------
  // per-tenant scoring-weight overrides
  // ------------------------------------------------------------------

  async getWeighting(appSource: string): Promise<JSONValue[]> {
    const result = await this.request("GET", `/tenants/my-apps/${encodeURIComponent(appSource)}/weighting`);
    return result.overrides;
  }

  /** ecm/pfm/pan/sda weights must each be in [0, 1] and sum to ~1.0
   * (server-enforced within 0.02 tolerance). */
  async setWeighting(
    appSource: string,
    area: string,
    sensitivityLevel: string,
    input: SetWeightingInput,
  ): Promise<JSONValue> {
    return this.request(
      "PUT",
      `/tenants/my-apps/${encodeURIComponent(appSource)}/weighting/${encodeURIComponent(area)}/${encodeURIComponent(sensitivityLevel)}`,
      {
        jsonBody: {
          ecm_weight: input.ecmWeight,
          pfm_weight: input.pfmWeight,
          pan_weight: input.panWeight,
          sda_weight: input.sdaWeight,
          approval_threshold: input.approvalThreshold,
          critical_framework_enforcement: input.criticalFrameworkEnforcement ?? false,
          require_human_review: input.requireHumanReview ?? false,
        },
      },
    );
  }

  async deleteWeighting(appSource: string, area: string, sensitivityLevel: string): Promise<JSONValue> {
    return this.request(
      "DELETE",
      `/tenants/my-apps/${encodeURIComponent(appSource)}/weighting/${encodeURIComponent(area)}/${encodeURIComponent(sensitivityLevel)}`,
    );
  }

  // ------------------------------------------------------------------
  // misc
  // ------------------------------------------------------------------

  /** Unauthenticated -- works without a token. */
  async health(): Promise<JSONValue> {
    return this.request("GET", "/health");
  }
}
