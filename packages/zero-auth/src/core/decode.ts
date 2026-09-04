import { decodeJwt } from "jose";
import type { AuthUser } from "../types/auth.js";
import { AuthError } from "../errors/authErrors.js";

/**
 * Decodes a JWT **without verifying the signature**.
 *
 * ⚠️ **Warning**: This function does NOT validate the token. The returned
 * payload may be from a tampered or expired token. Only use this when you
 * intentionally need to inspect a token without verification (e.g., reading
 * the `exp` claim before a refresh).
 *
 * @param token - The compact JWT string to decode.
 * @returns The decoded payload as `AuthUser`.
 * @throws {AuthError} with `AUTH_TOKEN_INVALID` if the token is malformed.
 */
export function decodeToken(token: string): AuthUser {
  try {
    const payload = decodeJwt(token);
    return payload as AuthUser;
  } catch {
    throw new AuthError("AUTH_TOKEN_INVALID", "Token is malformed and cannot be decoded.");
  }
}
