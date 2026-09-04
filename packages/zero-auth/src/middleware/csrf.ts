import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { AuthError } from "../errors/authErrors.js";
import { parseCookieHeader } from "../cookies/parseCookie.js";
import type { ResolvedConfig } from "../types/auth.js";

const MAX_TOKEN_LENGTH = 256;

/** Creates a signed, client-readable double-submit CSRF token cookie. */
export function createCsrfToken(res: Response, config: ResolvedConfig): string {
  const nonce = randomBytes(32).toString("base64url");
  const token = `${nonce}.${sign(nonce, config.accessSecret)}`;
  const options = config.cookies.options;

  res.cookie(config.csrf.cookieName, token, {
    httpOnly: false,
    ...(options.secure !== undefined && { secure: options.secure }),
    ...(options.sameSite !== undefined && { sameSite: options.sameSite }),
    ...(options.path !== undefined && { path: options.path }),
    ...(options.domain !== undefined && { domain: options.domain }),
  });

  return token;
}

/**
 * Creates cookie-aware CSRF middleware using the signed double-submit pattern.
 * Safe methods and requests without auth cookies pass through unchanged.
 */
export function createCsrfMiddleware(config: ResolvedConfig): RequestHandler {
  const protectedMethods = new Set(config.csrf.methods);

  return function csrf(req: Request, _res: Response, next: NextFunction): void {
    if (!protectedMethods.has(req.method.toUpperCase())) {
      next();
      return;
    }

    const hasAuthCookie =
      getCookie(req, config.cookies.accessTokenName) !== null ||
      getCookie(req, config.cookies.refreshTokenName) !== null;

    if (!hasAuthCookie) {
      next();
      return;
    }

    const cookieToken = getCookie(req, config.csrf.cookieName);
    const headerToken = req.get(config.csrf.headerName);

    if (
      !cookieToken ||
      !headerToken ||
      !isValidToken(cookieToken, headerToken, config.accessSecret)
    ) {
      next(new AuthError("AUTH_CSRF_INVALID"));
      return;
    }

    next();
  };
}

function getCookie(req: Request, name: string): string | null {
  const reqWithCookies = req as unknown as { cookies?: Record<string, unknown> };
  const parsedCookie = reqWithCookies.cookies?.[name];
  if (typeof parsedCookie === "string") return parsedCookie;

  const header = req.headers["cookie"];
  if (typeof header !== "string") return null;
  return parseCookieHeader(header)[name] ?? null;
}

function isValidToken(cookieToken: string, headerToken: string, secret: string): boolean {
  if (cookieToken.length > MAX_TOKEN_LENGTH || headerToken.length > MAX_TOKEN_LENGTH) return false;
  if (cookieToken !== headerToken) return false;

  const [nonce, signature, extra] = cookieToken.split(".");
  if (!nonce || !signature || extra !== undefined) return false;

  const expected = Buffer.from(sign(nonce, secret));
  const actual = Buffer.from(signature);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function sign(value: string, secret: string): string {
  return createHmac("sha256", secret).update(value).digest("base64url");
}
