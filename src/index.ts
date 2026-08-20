import type { RequestHandler, ErrorRequestHandler, Response } from "express";

import { createJwtEngine } from "./core/jwt.js";
import { createProtectMiddleware } from "./middleware/protect.js";
import { createAuthorizeMiddleware } from "./middleware/authorize.js";
import { createOptionalMiddleware } from "./middleware/optional.js";
import { createRefreshHandler, createRotateTokens } from "./refresh/refresh.js";
import { setCookie } from "./cookies/setCookie.js";
import { clearCookie } from "./cookies/clearCookie.js";
import { authErrorHandler } from "./errors/errorHandler.js";
import { resolveConfig, parseExpiryToSeconds, withFamilyId } from "./utils/helpers.js";

import type {
  AuthConfig,
  JwtPayload,
  AuthUser,
  TokenPair,
  ResolvedConfig,
} from "./types/auth.js";

// ─── Auth Instance Interface ─────────────────────────────────────────────────

/**
 * The full auth object returned by `createAuth()`.
 */
export interface AuthInstance {
  // ── Token Methods ──────────────────────────────────────────────────────────

  /**
   * Generates a signed access token for the given payload.
   * @example `const token = await auth.generateAccessToken({ id: "user-123" });`
   */
  generateAccessToken(payload: JwtPayload): Promise<string>;

  /**
   * Generates a signed refresh token for the given payload.
   * @example `const token = await auth.generateRefreshToken({ id: "user-123" });`
   */
  generateRefreshToken(payload: JwtPayload): Promise<string>;

  /**
   * Generates a matched access + refresh token pair in parallel.
   * @example `const { accessToken, refreshToken } = await auth.generateTokenPair({ id: "user-123", role: "user" });`
   */
  generateTokenPair(payload: JwtPayload): Promise<TokenPair>;

  /**
   * Verifies an access token and returns the decoded payload.
   * @throws `AuthError` when the token is missing, invalid, or expired.
   */
  verifyToken(token: string): Promise<AuthUser>;

  /** Verifies a refresh token and returns the decoded payload. */
  verifyRefreshToken(token: string): Promise<AuthUser>;

  /**
   * Decodes a token without verifying the signature. Never use this method as
   * authorization; use `verifyToken()` for trust decisions.
   */
  decodeToken(token: string): AuthUser;

  // ── Middleware ─────────────────────────────────────────────────────────────

  /**
   * Middleware: rejects unauthenticated requests with 401.
   * Attaches `req.user` on success.
   * @example `app.get("/profile", auth.protect(), profileHandler);`
   */
  protect(): RequestHandler;

  /**
   * Middleware: enforces role-based access. Must run after `protect()`.
   * Rejects requests where `req.user.role` is not in `allowedRoles` with 403.
   * @example `app.get("/admin", auth.protect(), auth.authorize(["admin"]), handler);`
   */
  authorize(allowedRoles: string[]): RequestHandler;

  /**
   * Middleware: optionally authenticates. Never rejects — populates `req.user`
   * if a valid token is present, otherwise continues as a guest.
   * @example `app.get("/posts", auth.optional(), postsHandler);`
   */
  optional(): RequestHandler;

  // ── Cookie Helpers ─────────────────────────────────────────────────────────

  /**
   * Sets both the access and refresh token as HTTP-only cookies on the response,
   * and returns the tokens as JSON. Use after login/register.
   * @example `const tokens = await auth.sendAuthTokens(res, { id: "user-123" });`
   */
  sendAuthTokens(res: Response, user: JwtPayload): Promise<TokenPair>;

  /**
   * Clears both auth cookies from the response. Use on logout.
   */
  clearAuth(res: Response): void;

  // ── Refresh ────────────────────────────────────────────────────────────────

  /**
   * Express route handler for `POST /auth/refresh`.
   * Validates the refresh token and issues a new access token.
   * @example `app.post("/auth/refresh", auth.refreshHandler());`
   */
  refreshHandler(): RequestHandler;

  /**
   * Generates a new token pair (access + refresh). Use for custom token rotation.
   */
  rotateTokens(payload: JwtPayload): Promise<TokenPair>;

  // ── Express App Integration ────────────────────────────────────────────────

  /**
   * Express error-handling middleware for AuthErrors.
   * Mount **after all routes** with `app.use(auth.errorHandler)`.
   * @example `app.use(auth.errorHandler);`
   */
  errorHandler: ErrorRequestHandler;

  // ── Internal ───────────────────────────────────────────────────────────────

  /** The fully resolved config (for advanced usage). */
  readonly config: ResolvedConfig;
}

// ─── Factory Function ─────────────────────────────────────────────────────────

/**
 * Creates a configured auth instance.
 *
 * @example
 * ```ts
 * import { createAuth } from "@0-auth/zero-auth";
 *
 * const auth = createAuth({
 *   accessSecret: process.env.JWT_ACCESS_SECRET!,
 *   refreshSecret: process.env.JWT_REFRESH_SECRET!,
 *   accessExpiresIn: "15m",
 *   refreshExpiresIn: "7d",
 * });
 *
 * app.get("/profile", auth.protect(), (req, res) => {
 *   res.json(req.user);
 * });
 *
 * app.use(auth.errorHandler);
 * ```
 */
export function createAuth(config: AuthConfig): AuthInstance {
  const resolved = resolveConfig(config);
  const engine = createJwtEngine(resolved);

  const rotateTokens = createRotateTokens(engine);

  return {
    config: resolved,

    // ── Token Methods ────────────────────────────────────────────────────────

    generateAccessToken(payload: JwtPayload) {
      return engine.generateAccessToken(payload);
    },

    generateRefreshToken(payload: JwtPayload) {
      return engine.generateRefreshToken(
        withFamilyId(payload, resolved.refreshOptions.rotate)
      );
    },

    generateTokenPair(payload: JwtPayload) {
      return engine.generateTokenPair(
        withFamilyId(payload, resolved.refreshOptions.rotate)
      );
    },

    verifyToken(token: string) {
      return engine.verifyAccessToken(token);
    },

    verifyRefreshToken(token: string) {
      return engine.verifyRefreshToken(token);
    },

    decodeToken(token: string) {
      return engine.decodeToken(token);
    },

    // ── Middleware ───────────────────────────────────────────────────────────

    protect() {
      return createProtectMiddleware(engine, resolved);
    },

    authorize(allowedRoles: string[]) {
      return createAuthorizeMiddleware(allowedRoles);
    },

    optional() {
      return createOptionalMiddleware(engine, resolved);
    },

    // ── Cookie Helpers ───────────────────────────────────────────────────────

    async sendAuthTokens(res: Response, user: JwtPayload): Promise<TokenPair> {
      const tokens = await engine.generateTokenPair(
        withFamilyId(user, resolved.refreshOptions.rotate)
      );

      setCookie(res, resolved.cookies.accessTokenName, tokens.accessToken, {
        ...resolved.cookies.options,
        maxAge: parseExpiryToSeconds(resolved.accessExpiresIn),
      });

      setCookie(res, resolved.cookies.refreshTokenName, tokens.refreshToken, {
        ...resolved.cookies.options,
        maxAge: parseExpiryToSeconds(resolved.refreshExpiresIn),
      });

      return tokens;
    },

    clearAuth(res: Response): void {
      clearCookie(res, resolved.cookies.accessTokenName, resolved.cookies.options);
      clearCookie(res, resolved.cookies.refreshTokenName, resolved.cookies.options);
    },

    // ── Refresh ──────────────────────────────────────────────────────────────

    refreshHandler() {
      return createRefreshHandler(engine, resolved);
    },

    rotateTokens(payload: JwtPayload) {
      return rotateTokens(payload);
    },

    // ── App Integration ──────────────────────────────────────────────────────

    errorHandler: authErrorHandler,
  };
}

// ─── Public Exports ───────────────────────────────────────────────────────────

// Types
export type {
  AuthConfig,
  CookieConfig,
  JwtPayload,
  AuthUser,
  TokenPair,
  ResolvedConfig,
  RefreshTokenContext,
  RefreshReuseContext,
} from "./types/auth.js";
export type { CookieOptions } from "./types/cookies.js";
export { extractToken, extractRefreshToken } from "./utils/extractToken.js";

// Errors
export { AuthError, isAuthError, AUTH_ERROR_CODES } from "./errors/authErrors.js";
export type { AuthErrorCode } from "./errors/authErrors.js";

// Standalone error handler (for use without the full createAuth() API)
export { authErrorHandler } from "./errors/errorHandler.js";

// Cookie utilities (for advanced usage)
export { setCookie } from "./cookies/setCookie.js";
export { clearCookie } from "./cookies/clearCookie.js";
export { parseCookieHeader } from "./cookies/parseCookie.js";

// Revocation helpers
export { createInMemoryRevocationStore } from "./refresh/inMemoryRevocationStore.js";

// Core utilities (for advanced usage)
export { signToken } from "./core/sign.js";
export { verifyToken } from "./core/verify.js";
export { decodeToken } from "./core/decode.js";
