import type { Response } from "express";
import type { CookieOptions } from "../types/cookies.js";

/**
 * Sets an HTTP-only cookie on the response.
 *
 * @param res - Express response object.
 * @param name - Cookie name.
 * @param value - Cookie value (e.g. a JWT string).
 * @param options - Cookie options (httpOnly is always enforced as true).
 */
export function setCookie(
  res: Response,
  name: string,
  value: string,
  options: CookieOptions = {}
): void {
  const {
    httpOnly = true,
    secure = process.env["NODE_ENV"] === "production",
    sameSite = "lax",
    path = "/",
    maxAge,
    domain,
  } = options;

  res.cookie(name, value, {
    httpOnly,
    secure,
    sameSite,
    path,
    ...(maxAge !== undefined && { maxAge: maxAge * 1000 }), // Express uses ms, we accept seconds
    ...(domain !== undefined && { domain }),
  });
}
