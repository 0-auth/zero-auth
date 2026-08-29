// ─── Error Codes ─────────────────────────────────────────────────────────────

export const AUTH_ERROR_CODES = {
  /** No token was found in the request (missing Authorization header or cookie). */
  AUTH_TOKEN_MISSING: "AUTH_TOKEN_MISSING",
  /** The token signature is invalid or the token is malformed. */
  AUTH_TOKEN_INVALID: "AUTH_TOKEN_INVALID",
  /** The token has expired. */
  AUTH_TOKEN_EXPIRED: "AUTH_TOKEN_EXPIRED",
  /** The user is not authenticated (generic 401). */
  AUTH_UNAUTHORIZED: "AUTH_UNAUTHORIZED",
  /** The user is authenticated but lacks the required role/permission (403). */
  AUTH_FORBIDDEN: "AUTH_FORBIDDEN",
  /** The request is missing or has an invalid CSRF token (403). */
  AUTH_CSRF_INVALID: "AUTH_CSRF_INVALID",
} as const;

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES];

// ─── HTTP Status Map ──────────────────────────────────────────────────────────

const STATUS_MAP: Record<AuthErrorCode, number> = {
  AUTH_TOKEN_MISSING: 401,
  AUTH_TOKEN_INVALID: 401,
  AUTH_TOKEN_EXPIRED: 401,
  AUTH_UNAUTHORIZED: 401,
  AUTH_FORBIDDEN: 403,
  AUTH_CSRF_INVALID: 403,
};

// ─── AuthError Class ─────────────────────────────────────────────────────────

/**
 * Typed error class for all authentication/authorization failures.
 *
 * @example
 * ```ts
 * throw new AuthError("AUTH_TOKEN_EXPIRED", "Your session has expired. Please log in again.");
 * ```
 */
export class AuthError extends Error {
  public readonly code: AuthErrorCode;
  public readonly statusCode: number;

  constructor(code: AuthErrorCode, message?: string) {
    super(message ?? defaultMessage(code));
    this.name = "AuthError";
    this.code = code;
    this.statusCode = STATUS_MAP[code];

    // Maintain proper prototype chain for `instanceof` checks.
    Object.setPrototypeOf(this, new.target.prototype);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Returns a JSON-serializable representation suitable for API error responses.
   */
  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        statusCode: this.statusCode,
      },
    };
  }
}

// ─── Type Guard ───────────────────────────────────────────────────────────────

/**
 * Type guard to check if an unknown value is an `AuthError`.
 */
export function isAuthError(value: unknown): value is AuthError {
  return value instanceof AuthError;
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

function defaultMessage(code: AuthErrorCode): string {
  switch (code) {
    case "AUTH_TOKEN_MISSING":
      return "Authentication token is missing.";
    case "AUTH_TOKEN_INVALID":
      return "Authentication token is invalid.";
    case "AUTH_TOKEN_EXPIRED":
      return "Authentication token has expired.";
    case "AUTH_UNAUTHORIZED":
      return "Unauthorized. Please log in.";
    case "AUTH_FORBIDDEN":
      return "Forbidden. You do not have permission to access this resource.";
    case "AUTH_CSRF_INVALID":
      return "CSRF token is missing or invalid.";
  }
}
