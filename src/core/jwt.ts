import { signToken } from "./sign.js";
import { verifyToken } from "./verify.js";
import { decodeToken } from "./decode.js";
import type { JwtPayload, AuthUser, TokenPair, ResolvedConfig } from "../types/auth.js";

/**
 * Core JWT engine bound to a resolved config.
 * Provides token generation, verification, and decoding with config baked in.
 */
export interface JwtEngine {
  /**
   * Generates a signed access token.
   * @param payload - The user claims to embed.
   */
  generateAccessToken(payload: JwtPayload): Promise<string>;

  /**
   * Generates a signed refresh token.
   * @param payload - The user claims to embed.
   */
  generateRefreshToken(payload: JwtPayload): Promise<string>;

  /**
   * Generates both an access and refresh token in parallel.
   * @param payload - The user claims to embed.
   */
  generateTokenPair(payload: JwtPayload): Promise<TokenPair>;

  /**
   * Verifies an access token and returns the decoded payload.
   * @throws {AuthError} on invalid, expired, or malformed tokens.
   */
  verifyAccessToken(token: string): Promise<AuthUser>;

  /**
   * Verifies a refresh token and returns the decoded payload.
   * @throws {AuthError} on invalid, expired, or malformed tokens.
   */
  verifyRefreshToken(token: string): Promise<AuthUser>;

  /**
   * Decodes a token without verifying the signature.
   * ⚠️ Use only for non-security-sensitive inspection.
   */
  decodeToken(token: string): AuthUser;
}

/**
 * Creates a JWT engine bound to the given resolved config.
 */
export function createJwtEngine(config: ResolvedConfig): JwtEngine {
  return {
    generateAccessToken(payload: JwtPayload): Promise<string> {
      return signToken(payload, config.accessSecret, config.accessExpiresIn, config.jwt);
    },

    generateRefreshToken(payload: JwtPayload): Promise<string> {
      return signToken(payload, config.refreshSecret, config.refreshExpiresIn, config.jwt);
    },

    async generateTokenPair(payload: JwtPayload): Promise<TokenPair> {
      const [accessToken, refreshToken] = await Promise.all([
        signToken(payload, config.accessSecret, config.accessExpiresIn, config.jwt),
        signToken(payload, config.refreshSecret, config.refreshExpiresIn, config.jwt),
      ]);
      return { accessToken, refreshToken };
    },

    verifyAccessToken(token: string): Promise<AuthUser> {
      return verifyToken(token, config.accessSecret, config.jwt);
    },

    verifyRefreshToken(token: string): Promise<AuthUser> {
      return verifyToken(token, config.refreshSecret, config.jwt);
    },

    decodeToken(token: string): AuthUser {
      return decodeToken(token);
    },
  };
}
