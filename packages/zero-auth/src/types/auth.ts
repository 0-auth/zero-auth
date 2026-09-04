import type { CookieOptions } from "./cookies.js";

// ─── Auth Configuration ─────────────────────────────────────────────────────

/**
 * Configuration passed to `createAuth()`.
 */
export interface AuthConfig {
  /** Secret used to sign access tokens (HS256). Min 32 chars recommended. */
  accessSecret: string;
  /** Secret used to sign refresh tokens (HS256). Min 32 chars recommended. */
  refreshSecret: string;
  /** Optional JWT claim validation policy shared by access and refresh tokens. */
  jwt?: JwtValidationConfig;
  /** Expiry for access tokens. Accepts zeit/ms strings like "15m", "1h". @default "15m" */
  accessExpiresIn?: string;
  /** Expiry for refresh tokens. Accepts zeit/ms strings like "7d", "30d". @default "7d" */
  refreshExpiresIn?: string;
  /** Cookie configuration. If provided, token cookies are enabled. */
  cookies?: CookieConfig;
  /** Optional CSRF protection for cookie-authenticated state-changing requests. */
  csrf?: CsrfConfig;
  /** Atomic refresh-token store used automatically when rotation is enabled. */
  refreshStore?: RefreshTokenStore;
  /** Optional refresh behavior configuration */
  refreshOptions?: {
    /**
     * When true, issue a new refresh token alongside the new access token.
     * Use `consumeRefreshToken` for atomic replay protection. In 1.1.x, the
     * legacy hook pair remains accepted with a warning.
     * A stable `fid` (family id) claim is auto-injected when missing.
     * @default false
     */
    rotate?: boolean;
    /**
     * Atomically consume the old refresh token before issuing replacements.
     * Return `true` only when this call marks the `jti` for the first time;
     * return `false` when it was already consumed. Use an atomic store
     * operation such as Redis `SET NX` for multi-instance deployments.
     */
    consumeRefreshToken?: (oldJti: string, ctx?: RefreshTokenContext) => Promise<boolean> | boolean;
    /**
     * Called with the old refresh token `jti` **before** new tokens are issued.
     * @deprecated Use `consumeRefreshToken` for concurrency-safe rotation.
     * Failures abort the refresh (fail closed). Optional second `ctx` includes
     * `userId` and `familyId` for family-aware stores.
     */
    revokeRefreshToken?: (oldJti: string, ctx?: RefreshTokenContext) => Promise<void> | void;
    /**
     * Called after a new refresh token is issued so stores can track the new
     * `jti` under its family (needed for family revocation on reuse).
     */
    registerRefreshToken?: (newJti: string, ctx: RefreshTokenContext) => Promise<void> | void;
    /** @deprecated Use `consumeRefreshToken` for concurrency-safe rotation. */
    isRevoked?: (jti: string) => Promise<boolean> | boolean;
    /**
     * Called when a revoked refresh token is presented (reuse detected).
     * Use this to revoke the entire token family / force re-login.
     */
    onRefreshReuse?: (ctx: RefreshReuseContext) => Promise<void> | void;
  };
}

/** Optional issuer, audience, and clock-skew policy for JWTs. */
export interface JwtValidationConfig {
  /** Expected `iss` claim. Added to new tokens and checked during verification. */
  issuer?: string;
  /** Expected `aud` claim. Added to new tokens and checked during verification. */
  audience?: string | string[];
  /** Allowed clock skew in seconds when validating time-based claims. */
  clockTolerance?: number;
}

/**
 * Context passed to refresh-token lifecycle hooks.
 */
export interface RefreshTokenContext {
  userId: string;
  /** Stable family id shared across rotated refresh tokens. */
  familyId?: string;
}

/**
 * Context for refresh-token reuse (replay) detection.
 */
export interface RefreshReuseContext extends RefreshTokenContext {
  jti: string;
}

/**
 * Application-owned store for concurrency-safe refresh-token rotation.
 * `consume()` must atomically return true only for the first use of a jti.
 */
export interface RefreshTokenStore {
  consume(jti: string, context?: RefreshTokenContext): Promise<boolean> | boolean;
  register?(jti: string, context: RefreshTokenContext): Promise<void> | void;
  revokeFamily?(familyId: string): Promise<void> | void;
}

/**
 * Cookie-specific configuration within AuthConfig.
 */
export interface CookieConfig {
  /** Name of the access token cookie. @default "access_token" */
  accessTokenName?: string;
  /** Name of the refresh token cookie. @default "refresh_token" */
  refreshTokenName?: string;
  /** Base cookie options applied to both token cookies. */
  options?: CookieOptions;
}

/** Configuration for the signed double-submit CSRF middleware. */
export interface CsrfConfig {
  /** Client-readable CSRF cookie name. @default "csrf_token" */
  cookieName?: string;
  /** Header carrying the token copied from the CSRF cookie. @default "x-csrf-token" */
  headerName?: string;
  /** HTTP methods to protect. @default ["POST", "PUT", "PATCH", "DELETE"] */
  methods?: string[];
}

// ─── Resolved Internal Config ────────────────────────────────────────────────

/**
 * Fully resolved config after defaults are applied. Used internally.
 */
export interface ResolvedConfig {
  accessSecret: string;
  refreshSecret: string;
  jwt: JwtValidationConfig;
  accessExpiresIn: string;
  refreshExpiresIn: string;
  cookies: Required<CookieConfig> & { options: CookieOptions };
  csrf: {
    cookieName: string;
    headerName: string;
    methods: string[];
  };
  refreshOptions: {
    rotate: boolean;
    consumeRefreshToken?: (oldJti: string, ctx?: RefreshTokenContext) => Promise<boolean> | boolean;
    revokeRefreshToken?: (oldJti: string, ctx?: RefreshTokenContext) => Promise<void> | void;
    registerRefreshToken?: (newJti: string, ctx: RefreshTokenContext) => Promise<void> | void;
    isRevoked?: (jti: string) => Promise<boolean> | boolean;
    onRefreshReuse?: (ctx: RefreshReuseContext) => Promise<void> | void;
  };
}

// ─── JWT Payload ─────────────────────────────────────────────────────────────

/**
 * The application-level data embedded in a JWT.
 */
export interface JwtPayload {
  /** Unique user identifier (required). */
  id: string;
  /** User email (optional). */
  email?: string;
  /** Primary user role for RBAC. */
  role?: string;
  /** Fine-grained permission strings. */
  permissions?: string[];
  /** Any additional custom claims. */
  [key: string]: unknown;
}

// ─── Token Pair ──────────────────────────────────────────────────────────────

/**
 * A pair of access and refresh tokens.
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// ─── Auth User ───────────────────────────────────────────────────────────────

/**
 * The decoded user object attached to `req.user` after middleware runs.
 */
export interface AuthUser extends JwtPayload {
  /** Token issued-at timestamp (seconds since epoch). */
  iat?: number;
  /** Token expiration timestamp (seconds since epoch). */
  exp?: number;
  /** Token ID (jti) if present */
  jti?: string;
}

declare global {
  namespace Express {
    interface Request {
      /**
       * The decoded JWT payload, attached by `auth.protect()` or `auth.optional()`.
       * `undefined` on unprotected routes.
       */
      user?: AuthUser;
    }
  }
}
