/**
 * Cookie options for setting HTTP-only auth cookies.
 */
export interface CookieOptions {
  /** Max age in seconds. If not set, cookie is session-only. */
  maxAge?: number;
  /** Restrict cookie to HTTPS. Defaults to true in production. */
  secure?: boolean;
  /** Prevent client-side JS access. Always true for auth cookies. */
  httpOnly?: boolean;
  /** SameSite policy. @default "lax" */
  sameSite?: "strict" | "lax" | "none";
  /** Cookie path. @default "/" */
  path?: string;
  /** Cookie domain. */
  domain?: string;
}
