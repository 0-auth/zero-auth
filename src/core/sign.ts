import { SignJWT } from "jose";
import type { JwtPayload, JwtValidationConfig } from "../types/auth.js";
import { parseExpiryToSeconds } from "../utils/helpers.js";

/**
 * Signs a JWT using HS256 (HMAC-SHA256) with the provided secret.
 *
 * @param payload - Application-level claims to embed.
 * @param secret - Signing secret (UTF-8 string).
 * @param expiresIn - Expiry string in zeit/ms format (e.g. "15m", "7d").
 * @param options - Optional issuer and audience claims.
 * @returns A compact JWT string.
 */
export async function signToken(
  payload: JwtPayload,
  secret: string,
  expiresIn: string,
  options?: JwtValidationConfig
): Promise<string> {
  const secretKey = new TextEncoder().encode(secret);

  let builder = new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + parseExpiryToSeconds(expiresIn))
    .setJti(generateJti());

  if (options?.issuer !== undefined) builder = builder.setIssuer(options.issuer);
  if (options?.audience !== undefined) builder = builder.setAudience(options.audience);

  const jwt = await builder.sign(secretKey);

  return jwt;
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/**
 * Generates a random JWT ID (jti) claim for token uniqueness.
 * Uses `crypto.randomUUID` (available in Node.js >= 14.17).
 */
function generateJti(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Fallback for older environments.
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}
