import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { JwtEngine } from "../core/jwt.js";
import type { ResolvedConfig } from "../types/auth.js";
import { AuthError } from "../errors/authErrors.js";
import { extractToken } from "../utils/extractToken.js";
import { logger } from "../utils/logger.js";

/**
 * Returns an Express middleware that protects a route by requiring a valid access token.
 *
 * On success: attaches the decoded user to `req.user` and calls `next()`.
 * On failure: calls `next(AuthError)` — caught by `authErrorHandler`.
 *
 * The token is read from (in priority order):
 * 1. `Authorization: Bearer <token>` header
 * 2. The access token cookie (if cookie config is set)
 *
 * @example
 * ```ts
 * app.get("/profile", auth.protect(), (req, res) => {
 *   res.json(req.user);
 * });
 * ```
 */
export function createProtectMiddleware(
  engine: JwtEngine,
  config: ResolvedConfig
): RequestHandler {
  return function protect(req: Request, _res: Response, next: NextFunction): void {
    const cookieName = config.cookies.accessTokenName;
    const token = extractToken(req, cookieName);

    if (!token) {
      logger.debug(`protect: no token found on ${req.method} ${req.path}`);
      next(new AuthError("AUTH_TOKEN_MISSING"));
      return;
    }

    engine
      .verifyAccessToken(token)
      .then((user) => {
        req.user = user;
        logger.debug(`protect: authenticated user ${user.id} on ${req.method} ${req.path}`);
        next();
      })
      .catch((err: unknown) => {
        if (err instanceof AuthError) {
          logger.debug(`protect: token error [${err.code}] on ${req.method} ${req.path}`);
          next(err);
        } else {
          logger.error("protect: unexpected error during token verification", err);
          next(new AuthError("AUTH_TOKEN_INVALID"));
        }
      });
  };
}
