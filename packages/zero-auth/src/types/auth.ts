import type { KeyLike } from "jose";
import type { CookieOptions } from "./cookies.js";

// ─── Supported Algorithms & Keys ─────────────────────────────────────────────

export type SymmetricAlgorithm = "HS256" | "HS384" | "HS512";
export type AsymmetricAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "EdDSA";

export type SupportedAlgorithm = SymmetricAlgorithm | AsymmetricAlgorithm;

/** Accepted key types for signing or verification. */
export type KeyInput = string | Uint8Array | KeyLike | object;

// ─── Auth Configuration ─────────────────────────────────────────────────────

/**
 * Configuration passed to `createAuth()`.
 */
export interface AuthConfig {
  /**
   * Secret used to sign access tokens (HS256/symmetric). Min 32 chars recommended.
   * Required when using symmetric algorithms unless asymmetric keys are provided.
   */
  accessSecret?: string;
  /**
   * Secret used to sign refresh tokens (HS256/symmetric). Min 32 chars recommended.
   * Required when using symmetric algorithms unless asymmetric keys are provided.
   */
  refreshSecret?: string;
  /**
   * JWT signing and verification algorithm.
   * Supports symmetric (HS256, HS384, HS512) and asymmetric (RS256, ES256, EdDSA, etc.).
   * @default "HS256"
   */
  algorithm?: SupportedAlgorithm;
  /**
   * Private key for signing access tokens (and refresh tokens if not overridden).
   * Accepts PKCS#8 PEM string, CryptoKey, or KeyLike.
   */
  privateKey?: KeyInput;
  /**
   * Public key for verifying access tokens (and refresh tokens if not overridden).
   * Accepts SPKI PEM string, CryptoKey, or KeyLike.
   */
  publicKey?: KeyInput;
  /**
   * Optional dedicated private key for signing refresh tokens.
   */
  refreshPrivateKey?: KeyInput;
  /**
   * Optional dedicated public key for verifying refresh tokens.
   */
  refreshPublicKey?: KeyInput;
  /**
   * Optional Key ID (`kid`) added to the protected header of signed JWTs.
   */
  keyId?: string;
  /**
   * Symmetric secret for signing double-submit CSRF tokens when JWTs use asymmetric keys.
   * Defaults to `accessSecret` if provided; otherwise required when CSRF is enabled with cookies.
   */
  csrfSecret?: string;
  /**
   * Remote JSON Web Key Set (JWKS) URL.
   * When provided, verification keys are fetched dynamically from this URL with caching and cooldown.
   * Sets verifier-only mode (token signing is disabled).
   * @example "https://auth.example.com/.well-known/jwks.json"
   */
  jwksUri?: string | URL;
  /**
   * Optional configuration for remote JWKS fetching, caching, and timeouts.
   */
  jwks?: RemoteJwksConfig;
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
     * Reloads current application-owned user claims before a refresh succeeds.
     * Return `null` to reject deleted, disabled, or otherwise ineligible users.
     */
    resolveUser?: (
      claims: JwtPayload,
      ctx: RefreshTokenContext
    ) => Promise<JwtPayload | null> | JwtPayload | null;
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

/** Configuration options for remote JWKS key fetching and caching. */
export interface RemoteJwksConfig {
  /** Maximum age of cached keys in milliseconds. @default 600000 (10 minutes) */
  cacheMaxAge?: number;
  /** Cooldown duration in milliseconds after an unmatched key before refetching. @default 30000 (30 seconds) */
  cooldownDuration?: number;
  /** Timeout in milliseconds for fetching the remote JWKS. @default 5000 (5 seconds) */
  timeoutDuration?: number;
  /** Optional custom HTTP headers sent with the JWKS request. */
  headers?: Record<string, string>;
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
  /** Optional symmetric secret for signing CSRF tokens. */
  secret?: string;
}

// ─── Resolved Internal Config ────────────────────────────────────────────────

/**
 * Fully resolved config after defaults are applied. Used internally.
 */
export interface ResolvedConfig {
  algorithm: SupportedAlgorithm;
  isAsymmetric: boolean;
  isVerifierOnly: boolean;
  isJwks: boolean;
  jwksUri?: string;
  jwks?: RemoteJwksConfig;
  accessSecret?: string;
  refreshSecret?: string;
  privateKey?: KeyInput;
  publicKey?: KeyInput;
  refreshPrivateKey?: KeyInput;
  refreshPublicKey?: KeyInput;
  keyId?: string;
  csrfSecret?: string;
  jwt: JwtValidationConfig;
  accessExpiresIn: string;
  refreshExpiresIn: string;
  cookies: Required<CookieConfig> & { options: CookieOptions };
  csrf: {
    cookieName: string;
    headerName: string;
    methods: string[];
    secret?: string;
  };
  refreshOptions: {
    rotate: boolean;
    resolveUser?: (
      claims: JwtPayload,
      ctx: RefreshTokenContext
    ) => Promise<JwtPayload | null> | JwtPayload | null;
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
