import { SignJWT } from "jose";
import type { JwtPayload, JwtValidationConfig, SupportedAlgorithm } from "../types/auth.js";
import { parseExpiryToSeconds } from "../utils/helpers.js";
import { importKeyInput, type ResolvedKey } from "./keys.js";

export interface SignTokenOptions extends JwtValidationConfig {
  /** JWT algorithm to use for signing. @default "HS256" */
  algorithm?: SupportedAlgorithm;
  /** Optional Key ID to set in the protected header (`kid`). */
  keyId?: string;
}

/**
 * Signs a JWT using the specified algorithm and key.
 *
 * @param payload - Application-level claims to embed.
 * @param keyOrSecret - Signing secret string, PEM string, Uint8Array, or CryptoKey/KeyLike.
 * @param expiresIn - Expiry string in zeit/ms format (e.g. "15m", "7d").
 * @param options - Optional issuer, audience, algorithm, and keyId options.
 * @returns A compact JWT string.
 */
export async function signToken(
  payload: JwtPayload,
  keyOrSecret: ResolvedKey | string,
  expiresIn: string,
  options?: SignTokenOptions
): Promise<string> {
  const alg: SupportedAlgorithm = options?.algorithm ?? "HS256";

  const key: ResolvedKey =
    typeof keyOrSecret === "string" ? await importKeyInput(keyOrSecret, alg, "sign") : keyOrSecret;

  let builder = new SignJWT({ ...payload })
    .setProtectedHeader({
      alg,
      typ: "JWT",
      ...(options?.keyId !== undefined && { kid: options.keyId }),
    })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + parseExpiryToSeconds(expiresIn))
    .setJti(generateJti());

  if (options?.issuer !== undefined) builder = builder.setIssuer(options.issuer);
  if (options?.audience !== undefined) builder = builder.setAudience(options.audience);

  // jose's SignJWT.sign accepts KeyLike | Uint8Array
  const jwt = await builder.sign(key);

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
