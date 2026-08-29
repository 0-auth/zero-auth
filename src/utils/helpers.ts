import type { AuthConfig, ResolvedConfig, JwtPayload, AuthUser } from "../types/auth.js";
import type { CookieOptions } from "../types/cookies.js";

// ─── Default Values ───────────────────────────────────────────────────────────

const DEFAULT_ACCESS_EXPIRES_IN = "15m";
const DEFAULT_REFRESH_EXPIRES_IN = "7d";
const DEFAULT_ACCESS_COOKIE_NAME = "access_token";
const DEFAULT_REFRESH_COOKIE_NAME = "refresh_token";
const DEFAULT_CSRF_COOKIE_NAME = "csrf_token";
const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
const DEFAULT_CSRF_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: process.env["NODE_ENV"] === "production",
  sameSite: "lax",
  path: "/",
};

/** Registered JWT claims that must not be copied into a new signed payload. */
const REGISTERED_JWT_CLAIMS = new Set([
  "iat",
  "exp",
  "nbf",
  "jti",
  "iss",
  "aud",
  "sub",
  "typ",
  "alg",
]);

// ─── Config Merger ────────────────────────────────────────────────────────────

/**
 * Merges user-provided `AuthConfig` with secure defaults, producing a
 * fully-resolved internal config.
 */
export function resolveConfig(config: AuthConfig): ResolvedConfig {
  validateSecrets(config);
  validateRefreshOptions(config);

  const accessTokenName = config.cookies?.accessTokenName ?? DEFAULT_ACCESS_COOKIE_NAME;
  const refreshTokenName = config.cookies?.refreshTokenName ?? DEFAULT_REFRESH_COOKIE_NAME;
  const csrf = resolveCsrfConfig(config, accessTokenName, refreshTokenName);

  return {
    accessSecret: config.accessSecret,
    refreshSecret: config.refreshSecret,
    accessExpiresIn: config.accessExpiresIn ?? DEFAULT_ACCESS_EXPIRES_IN,
    refreshExpiresIn: config.refreshExpiresIn ?? DEFAULT_REFRESH_EXPIRES_IN,
    cookies: {
      accessTokenName,
      refreshTokenName,
      options: ((): CookieOptions => {
        const merged: CookieOptions = {
          ...DEFAULT_COOKIE_OPTIONS,
          ...config.cookies?.options,
          // httpOnly is always true — never allow it to be overridden for security.
          httpOnly: true,
        };

        // Validate SameSite/Secure relationship: SameSite=None requires Secure.
        if (merged.sameSite === "none" && merged.secure === false) {
          const msg =
            "[zero-auth] Cookie option " +
            "`sameSite: 'none'` requires `secure: true` to work in modern browsers.";
          if (process.env["NODE_ENV"] === "production") {
            throw new Error(msg);
          } else {
            console.warn(`WARNING: ${msg}`);
          }
        }

        return merged;
      })(),
    },
    csrf,
    refreshOptions: {
      rotate: config.refreshOptions?.rotate ?? false,
      ...(config.refreshOptions?.consumeRefreshToken
        ? { consumeRefreshToken: config.refreshOptions.consumeRefreshToken }
        : {}),
      ...(config.refreshOptions?.revokeRefreshToken
        ? { revokeRefreshToken: config.refreshOptions.revokeRefreshToken }
        : {}),
      ...(config.refreshOptions?.registerRefreshToken
        ? { registerRefreshToken: config.refreshOptions.registerRefreshToken }
        : {}),
      ...(config.refreshOptions?.isRevoked ? { isRevoked: config.refreshOptions.isRevoked } : {}),
      ...(config.refreshOptions?.onRefreshReuse
        ? { onRefreshReuse: config.refreshOptions.onRefreshReuse }
        : {}),
    },
  };
}

function resolveCsrfConfig(
  config: AuthConfig,
  accessTokenName: string,
  refreshTokenName: string
): ResolvedConfig["csrf"] {
  const cookieName = config.csrf?.cookieName ?? DEFAULT_CSRF_COOKIE_NAME;
  const headerName = config.csrf?.headerName ?? DEFAULT_CSRF_HEADER_NAME;
  const methods = config.csrf?.methods ?? DEFAULT_CSRF_METHODS;

  if (!cookieName.trim() || !headerName.trim()) {
    throw new Error("[zero-auth] CSRF cookieName and headerName cannot be empty.");
  }
  if (cookieName === accessTokenName || cookieName === refreshTokenName) {
    throw new Error("[zero-auth] CSRF cookieName must differ from auth cookie names.");
  }
  if (
    !Array.isArray(methods) ||
    methods.length === 0 ||
    methods.some((method) => typeof method !== "string" || !method.trim())
  ) {
    throw new Error("[zero-auth] CSRF methods must contain at least one non-empty method.");
  }

  return {
    cookieName,
    headerName,
    methods: [...new Set(methods.map((method) => method.trim().toUpperCase()))],
  };
}

// ─── Payload Helpers ──────────────────────────────────────────────────────────

/**
 * Builds a signable payload from a verified token, keeping application claims
 * (including custom ones) and stripping registered JWT claims.
 */
export function toRefreshPayload(decoded: AuthUser): JwtPayload {
  const payload: JwtPayload = { id: decoded.id };

  for (const [key, value] of Object.entries(decoded)) {
    if (key === "id" || REGISTERED_JWT_CLAIMS.has(key)) continue;
    if (value !== undefined) {
      payload[key] = value;
    }
  }

  return payload;
}

/**
 * Ensures a stable refresh-token family id (`fid`) is present when rotation
 * is enabled. Existing `fid` values are preserved across rotations.
 */
export function withFamilyId(payload: JwtPayload, rotate: boolean): JwtPayload {
  if (!rotate) return payload;
  if (typeof payload["fid"] === "string" && payload["fid"].length > 0) {
    return payload;
  }

  const fid =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;

  return { ...payload, fid };
}

// ─── Expiry Parser ────────────────────────────────────────────────────────────

/**
 * Converts a zeit/ms-style string (e.g. "15m", "7d", "1h") to seconds.
 * Used for setting cookie `maxAge` values.
 */
export function parseExpiryToSeconds(expiry: string): number {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h|d|w)$/.exec(expiry);
  if (!match) {
    throw new Error(
      `Invalid expiry format: "${expiry}". Expected a string like "15m", "1h", "7d".`
    );
  }

  const value = parseFloat(match[1]!);
  const unit = match[2]!;

  const multipliers: Record<string, number> = {
    ms: 0.001,
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
  };

  return Math.floor(value * (multipliers[unit] ?? 1));
}

// ─── Validation ───────────────────────────────────────────────────────────────

/**
 * Validates that secrets are present and of sufficient length.
 * Warns in development if secrets appear weak.
 */
function validateSecrets(config: AuthConfig): void {
  if (!config.accessSecret) {
    throw new Error("[zero-auth] `accessSecret` is required.");
  }
  if (!config.refreshSecret) {
    throw new Error("[zero-auth] `refreshSecret` is required.");
  }

  const isProd = process.env["NODE_ENV"] === "production";

  if (config.accessSecret.length < 32) {
    const msg = "[zero-auth] `accessSecret` should be at least 32 characters for security.";
    if (isProd) throw new Error(msg);
    console.warn(`WARNING: ${msg}`);
  }
  if (config.refreshSecret.length < 32) {
    const msg = "[zero-auth] `refreshSecret` should be at least 32 characters for security.";
    if (isProd) throw new Error(msg);
    console.warn(`WARNING: ${msg}`);
  }
  if (config.accessSecret === config.refreshSecret) {
    const msg = "[zero-auth] `accessSecret` and `refreshSecret` should be different values.";
    if (isProd) throw new Error(msg);
    console.warn(`WARNING: ${msg}`);
  }
}

/** Rotation without an atomic consume operation is unsafe under concurrency. */
function validateRefreshOptions(config: AuthConfig): void {
  if (!config.refreshOptions?.rotate) return;

  const isProd = process.env["NODE_ENV"] === "production";
  if (typeof config.refreshOptions.consumeRefreshToken === "function") return;

  const missing: string[] = [];
  if (typeof config.refreshOptions.isRevoked !== "function") missing.push("isRevoked");
  if (typeof config.refreshOptions.revokeRefreshToken !== "function") {
    missing.push("revokeRefreshToken");
  }

  if (missing.length > 0) {
    const msg =
      `[zero-auth] refreshOptions.rotate requires ${missing.join(" and ")} ` +
      "for legacy refresh-token replay protection.";
    if (isProd) throw new Error(msg);
    console.warn(`WARNING: ${msg}`);
    return;
  }

  console.warn(
    "WARNING: [zero-auth] isRevoked + revokeRefreshToken are deprecated and " +
      "not concurrency-safe; use consumeRefreshToken."
  );
}
