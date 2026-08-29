import { jwtVerify, errors as joseErrors } from "jose";
import type { AuthUser } from "../types/auth.js";
import { AuthError } from "../errors/authErrors.js";

/**
 * Verifies a JWT using HS256 and returns the decoded payload.
 *
 * @param token - The compact JWT string to verify.
 * @param secret - The signing secret.
 * @returns The decoded `AuthUser` payload.
 * @throws {AuthError} with the appropriate code on any verification failure.
 */
export async function verifyToken(token: string, secret: string): Promise<AuthUser> {
  const secretKey = new TextEncoder().encode(secret);

  try {
    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ["HS256"],
    });

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
      errName === "JWTInvalid" ||
      errName === "JWSInvalid" ||
      errName === "JWSSignatureVerificationFailed"
    ) {
      throw new AuthError("AUTH_TOKEN_INVALID");
    }

    // Any other jose error is treated as invalid.
    throw new AuthError("AUTH_TOKEN_INVALID", "Token verification failed.");
  }
}
