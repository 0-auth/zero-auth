import { jwtVerify, errors as joseErrors } from "jose";
import type { AuthUser, JwtValidationConfig, SupportedAlgorithm } from "../types/auth.js";
import { AuthError } from "../errors/authErrors.js";
import { importKeyInput, type VerificationKey } from "./keys.js";

export interface VerifyTokenOptions extends JwtValidationConfig {
  /** The expected JWT algorithm. @default "HS256" */
  algorithm?: SupportedAlgorithm;
  /** Explicit allowed algorithms whitelist (overrides algorithm). */
  algorithms?: SupportedAlgorithm[];
}

/**
 * Verifies a JWT and returns the decoded payload.
 *
 * @param token - The compact JWT string to verify.
 * @param keyOrSecret - Verification public key PEM, secret string, Uint8Array, KeyLike, or JWKS resolver.
 * @param options - Optional issuer, audience, clockTolerance, and algorithm options.
 * @returns The decoded `AuthUser` payload.
 * @throws {AuthError} with the appropriate code on any verification failure.
 */
export async function verifyToken(
  token: string,
  keyOrSecret: VerificationKey | string,
  options?: VerifyTokenOptions
): Promise<AuthUser> {
  const isJwks = typeof keyOrSecret === "function";

  const alg: SupportedAlgorithm = options?.algorithm ?? "HS256";
  const algorithms: string[] | undefined =
    options?.algorithms ??
    (options?.algorithm ? [options.algorithm] : isJwks ? undefined : ["HS256"]);

  const key: VerificationKey =
    typeof keyOrSecret === "string"
      ? await importKeyInput(keyOrSecret, alg, "verify")
      : keyOrSecret;

  try {
    const jwtVerifyOptions = {
      ...(algorithms !== undefined && { algorithms }),
      ...(options?.issuer !== undefined && { issuer: options.issuer }),
      ...(options?.audience !== undefined && { audience: options.audience }),
      ...(options?.clockTolerance !== undefined && {
        clockTolerance: options.clockTolerance,
      }),
    };

    const { payload } =
      typeof key === "function"
        ? await jwtVerify(token, key, jwtVerifyOptions)
        : await jwtVerify(token, key, jwtVerifyOptions);

    // Ensure the `id` claim is present (required by JwtPayload).
    if (typeof payload["id"] !== "string") {
      throw new AuthError(
        "AUTH_TOKEN_INVALID",
        "Token payload is missing the required `id` claim."
      );
    }

    return payload as AuthUser;
  } catch (err) {
    if (err instanceof AuthError) throw err;

    // jose may throw platform-specific error classes; fall back to checking `name`.
    const errName = (err as { name?: string } | null)?.name;

    if (
      err instanceof joseErrors.JWTExpired ||
      errName === "JWTExpired" ||
      errName === "TokenExpiredError"
    ) {
      throw new AuthError("AUTH_TOKEN_EXPIRED");
    }

    if (
      err instanceof joseErrors.JWTInvalid ||
      err instanceof joseErrors.JWSInvalid ||
      err instanceof joseErrors.JWSSignatureVerificationFailed ||
      err instanceof joseErrors.JWKSNoMatchingKey ||
      err instanceof joseErrors.JWKSMultipleMatchingKeys ||
      err instanceof joseErrors.JWKSTimeout ||
      errName === "JWTInvalid" ||
      errName === "JWSInvalid" ||
      errName === "JWSSignatureVerificationFailed" ||
      errName === "JWKSNoMatchingKey" ||
      errName === "JWKSMultipleMatchingKeys" ||
      errName === "JWKSTimeout"
    ) {
      throw new AuthError("AUTH_TOKEN_INVALID");
    }

    // Any other verification/network error is treated as invalid.
    throw new AuthError(
      "AUTH_TOKEN_INVALID",
      (err as Error).message || "Token verification failed."
    );
  }
}
