/** Exceptions raised by the CGC Core SDK. */

/** Base class for every error this SDK throws. */
export class CGCCoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CGCCoreError";
  }
}

/**
 * The API responded with a 4xx/5xx status. Mirrors the {"detail": "..."}
 * shape every CGC Core endpoint uses for error responses (FastAPI's
 * default HTTPException body).
 */
export class CGCCoreAPIError extends CGCCoreError {
  statusCode: number;
  detail: unknown;
  responseBody?: string;

  constructor(statusCode: number, detail: unknown, responseBody?: string) {
    super(`CGC Core API error ${statusCode}: ${JSON.stringify(detail)}`);
    this.name = "CGCCoreAPIError";
    this.statusCode = statusCode;
    this.detail = detail;
    this.responseBody = responseBody;
  }
}

/**
 * 401/403 from the API -- missing, expired, or insufficiently-scoped
 * credential. Kept distinct from CGCCoreAPIError so callers can catch it
 * separately (e.g. to trigger a re-login) without string-matching status
 * codes themselves.
 */
export class CGCCoreAuthError extends CGCCoreAPIError {
  constructor(statusCode: number, detail: unknown, responseBody?: string) {
    super(statusCode, detail, responseBody);
    this.name = "CGCCoreAuthError";
  }
}
