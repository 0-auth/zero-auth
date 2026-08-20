import type { Request } from "express";
import { parseCookieHeader } from "../cookies/parseCookie.js";

/**
 * Extracts a Bearer token from the `Authorization` header.
 * Returns `null` if the header is absent or not a Bearer token.
 */
function fromAuthorizationHeader(req: Request): string | null {
  const authHeader = req.headers["authorization"];
  if (!authHeader || typeof authHeader !== "string") return null;

  const match = /^Bearer\s+(\S+)/i.exec(authHeader.trim());
  return match?.[1] ?? null;
}

/**
 * Extracts a token from a named cookie.
 * Returns `null` if the cookie is absent.
 *
 * Works with both the raw `Cookie` header parser and `req.cookies`
 * (if cookie-parser is installed).
 */
function fromCookie(req: Request, cookieName: string): string | null {
  // If cookie-parser is installed, use req.cookies directly.
  // We cast through unknown to avoid importing cookie-parser types as a hard dependency.
  const reqWithCookies = req as unknown as { cookies?: Record<string, string> };
  if (reqWithCookies.cookies && typeof reqWithCookies.cookies[cookieName] === "string") {
    return reqWithCookies.cookies[cookieName] ?? null;
  }

  // Fallback: parse the raw Cookie header manually.
  const cookieHeader = req.headers["cookie"];
  if (!cookieHeader) return null;

  return parseCookieHeader(cookieHeader)[cookieName] ?? null;
}

/**
 * Extracts a refresh token from JSON body fields (common for non-cookie clients).
 */
function fromBody(req: Request): string | null {
  const body = req.body as unknown;
  if (!body || typeof body !== "object") return null;

  const record = body as Record<string, unknown>;
  const candidate = record["refreshToken"] ?? record["refresh_token"];
  return typeof candidate === "string" && candidate.length > 0 ? candidate : null;
}

/**
 * Extracts an access token from either:
 * 1. The `Authorization: Bearer <token>` header (preferred), or
 * 2. A named cookie (fallback, requires `cookieName` to be set in config).
 *
 * Returns `null` if no token is found.
 */
export function extractToken(req: Request, cookieName?: string): string | null {
  return fromAuthorizationHeader(req) ?? (cookieName ? fromCookie(req, cookieName) : null);
}

/**
 * Extracts a refresh token with SPA-safe priority:
 * 1. Named refresh cookie (avoids colliding with an access Bearer header),
 * 2. JSON body `refreshToken` / `refresh_token`,
 * 3. `Authorization: Bearer` (API clients that send only the refresh token).
 *
 * Returns `null` if no token is found.
 */
export function extractRefreshToken(req: Request, cookieName?: string): string | null {
  if (cookieName) {
    const fromRefreshCookie = fromCookie(req, cookieName);
    if (fromRefreshCookie) return fromRefreshCookie;
  }

  return fromBody(req) ?? fromAuthorizationHeader(req);
}
