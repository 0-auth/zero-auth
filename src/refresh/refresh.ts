import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { JwtEngine } from "../core/jwt.js";
import type { ResolvedConfig, JwtPayload, RefreshTokenContext } from "../types/auth.js";
import { AuthError } from "../errors/authErrors.js";
import { extractRefreshToken } from "../utils/extractToken.js";
import { setCookie } from "../cookies/setCookie.js";
import {
  parseExpiryToSeconds,
  toRefreshPayload,
  withFamilyId,
} from "../utils/helpers.js";
import { logger } from "../utils/logger.js";

/**
 * Creates an Express route handler for refreshing access tokens.
 *
 * Mount this at `POST /auth/refresh`. The handler reads the refresh token from
 * (in order) the refresh cookie, JSON body, or `Authorization: Bearer` header,
 * verifies it, and issues a new access token.
 *
 * When `refreshOptions.rotate` is enabled, a new refresh token is issued after
 * the previous `jti` is revoked (fail closed). Reuse of a revoked token triggers
 * `onRefreshReuse` so callers can invalidate the token family.
 *
 * @example
 * ```ts
 * app.post("/auth/refresh", auth.refreshHandler());
 * ```
 */
export function createRefreshHandler(engine: JwtEngine, config: ResolvedConfig): RequestHandler {
  return function refreshHandler(req: Request, res: Response, next: NextFunction): void {
    const cookieName = config.cookies.refreshTokenName;
    const token = extractRefreshToken(req, cookieName);

    if (!token) {
      next(new AuthError("AUTH_TOKEN_MISSING", "Refresh token is missing."));
      return;
    }

    engine
      .verifyRefreshToken(token)
      .then(async (decoded) => {
        const payload = withFamilyId(
          toRefreshPayload(decoded),
          config.refreshOptions.rotate
        );

        const familyId =
          typeof payload["fid"] === "string" ? (payload["fid"] as string) : undefined;
        const tokenCtx: RefreshTokenContext = {
          userId: payload.id,
          ...(familyId !== undefined && { familyId }),
        };
        const incomingJti = decoded.jti;

        // Reject reused / revoked refresh tokens before issuing anything new.
        if (incomingJti && typeof config.refreshOptions.isRevoked === "function") {
          try {
            const revoked = await Promise.resolve(config.refreshOptions.isRevoked(incomingJti));
            if (revoked) {
              if (typeof config.refreshOptions.onRefreshReuse === "function") {
                try {
                  await Promise.resolve(
                    config.refreshOptions.onRefreshReuse({
                      jti: incomingJti,
                      ...tokenCtx,
                    })
                  );
                } catch (reuseErr) {
                  logger.warn("refreshHandler: onRefreshReuse hook threw an error", reuseErr);
                }
              }
              next(new AuthError("AUTH_TOKEN_INVALID", "Refresh token has been revoked."));
              return;
            }
          } catch (chkErr) {
            logger.warn("refreshHandler: isRevoked hook threw an error", chkErr);
            next(new AuthError("AUTH_TOKEN_INVALID", "Failed revocation check."));
            return;
          }
        }

        // Rotation: revoke old jti BEFORE issuing replacements (fail closed).
        if (config.refreshOptions.rotate) {
          if (incomingJti && typeof config.refreshOptions.revokeRefreshToken === "function") {
            try {
              await Promise.resolve(
                config.refreshOptions.revokeRefreshToken(incomingJti, tokenCtx)
              );
            } catch (hookErr) {
              logger.warn("refreshHandler: revokeRefreshToken hook threw an error", hookErr);
              next(
                new AuthError(
                  "AUTH_TOKEN_INVALID",
                  "Failed to revoke previous refresh token."
                )
              );
              return;
            }
          }

          const { accessToken, refreshToken } = await engine.generateTokenPair(payload);

          if (typeof config.refreshOptions.registerRefreshToken === "function") {
            try {
              const newClaims = engine.decodeToken(refreshToken);
              if (newClaims.jti) {
                await Promise.resolve(
                  config.refreshOptions.registerRefreshToken(newClaims.jti, tokenCtx)
                );
              }
            } catch (regErr) {
              logger.warn("refreshHandler: registerRefreshToken hook threw an error", regErr);
              // Old token is already revoked; refuse to return tokens we cannot track.
              next(
                new AuthError(
                  "AUTH_TOKEN_INVALID",
                  "Failed to register rotated refresh token."
                )
              );
              return;
            }
          }

          setCookie(res, config.cookies.accessTokenName, accessToken, {
            ...config.cookies.options,
            maxAge: parseExpiryToSeconds(config.accessExpiresIn),
          });

          setCookie(res, config.cookies.refreshTokenName, refreshToken, {
            ...config.cookies.options,
            maxAge: parseExpiryToSeconds(config.refreshExpiresIn),
          });

          logger.debug(`refreshHandler: rotated refresh token for user ${payload.id}`);

          res.json({ accessToken, refreshToken });
          return;
        }

        // Default (stateless) behavior: issue a new access token only.
        const newAccessToken = await engine.generateAccessToken(payload);

        setCookie(res, config.cookies.accessTokenName, newAccessToken, {
          ...config.cookies.options,
          maxAge: parseExpiryToSeconds(config.accessExpiresIn),
        });

        logger.debug(`refreshHandler: issued new access token for user ${payload.id}`);

        res.json({ accessToken: newAccessToken });
      })
      .catch((err: unknown) => {
        if (err instanceof AuthError) {
          next(err);
        } else {
          logger.error("refreshHandler: unexpected error", err);
          next(new AuthError("AUTH_TOKEN_INVALID", "Failed to process refresh token."));
        }
      });
  };
}

/**
 * Token rotation: generates a new refresh token alongside the access token.
 *
 * Use this in a custom refresh endpoint when you want to implement
 * refresh token rotation (each refresh invalidates the old token).
 *
 * @example
 * ```ts
 * app.post("/auth/refresh", async (req, res, next) => {
 *   try {
 *     const { accessToken, refreshToken } = await auth.rotateTokens(payload);
 *     res.json({ accessToken, refreshToken });
 *   } catch (err) {
 *     next(err);
 *   }
 * });
 * ```
 */
export function createRotateTokens(engine: JwtEngine) {
  return async function rotateTokens(
    payload: JwtPayload
  ): Promise<{ accessToken: string; refreshToken: string }> {
    return engine.generateTokenPair(payload);
  };
}
