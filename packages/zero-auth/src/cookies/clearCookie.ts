import type { Response } from "express";
import type { CookieOptions } from "../types/cookies.js";

/**
 * Clears a named cookie from the response.
 *
 * Sends a `Set-Cookie` header with an expired `Max-Age` to instruct
 * the browser to delete the cookie. Attributes should match those used
 * when the cookie was set (path, domain, sameSite, secure).
 *
 * @param res - Express response object.
 * @param name - The name of the cookie to clear.
 * @param optionsOrPath - Cookie options, or a path string for backward compatibility.
 */
export function clearCookie(
  res: Response,
  name: string,
  optionsOrPath: CookieOptions | string = {}
): void {
  const options: CookieOptions =
    typeof optionsOrPath === "string" ? { path: optionsOrPath } : optionsOrPath;

  const {
    path = "/",
    secure = process.env["NODE_ENV"] === "production",
    sameSite = "lax",
    domain,
    httpOnly = true,
  } = options;

  res.clearCookie(name, {
    httpOnly,
    path,
    sameSite,
    secure,
    ...(domain !== undefined && { domain }),
  });
}
