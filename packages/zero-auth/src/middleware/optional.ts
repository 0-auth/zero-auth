import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { JwtEngine } from "../core/jwt.js";
import type { ResolvedConfig } from "../types/auth.js";
import { AuthError } from "../errors/authErrors.js";
import { extractToken } from "../utils/extractToken.js";
import { logger } from "../utils/logger.js";

/**
 * Returns an Express middleware that **optionally** authenticates a request.
 *
 * Unlike `protect()`, this middleware never rejects the request.
 * If a valid token is present, `req.user` is populated.
 * If no token or an invalid token is present, `req.user` remains `undefined`
 * and `next()` is called normally.
 *
 * Useful for public routes that benefit from knowing the current user
 * (e.g., showing personalised content or rate-limiting by user).
 *
 * @example
 * ```ts
 * app.get("/posts", auth.optional(), (req, res) => {
 *   if (req.user) {
 *     // Return personalised feed
 *   } else {
 *     // Return public feed
 *   }
 * });
 * ```
 */
export function createOptionalMiddleware(
  engine: JwtEngine,
  config: ResolvedConfig
): RequestHandler {
  return function optional(req: Request, _res: Response, next: NextFunction): void {
    const cookieName = config.cookies.accessTokenName;
    const token = extractToken(req, cookieName);

    if (!token) {
      next();
      return;
    }

    engine
      .verifyAccessToken(token)
      .then((user) => {
        req.user = user;
        logger.debug(`optional: authenticated user ${user.id}`);
        next();
      })
      .catch((err: unknown) => {
        // For optional auth, silently ignore auth errors.
        if (err instanceof AuthError) {
          logger.debug(`optional: ignoring token error [${err.code}]`);
        } else {
          logger.warn("optional: unexpected error during token verification", err);
        }
        next();
      });
  };
}
