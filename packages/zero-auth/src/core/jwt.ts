import { signToken } from "./sign.js";
import { verifyToken } from "./verify.js";
import { decodeToken } from "./decode.js";
import { createKeyResolver, createJwksResolver } from "./keys.js";
import type {
  JwtPayload,
  AuthUser,
  TokenPair,
  ResolvedConfig,
  SupportedAlgorithm,
} from "../types/auth.js";

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
  const jwksResolver =
    config.isJwks && config.jwksUri ? createJwksResolver(config.jwksUri, config.jwks) : undefined;

  const accessSigningInput = config.privateKey ?? config.accessSecret;
  const accessVerificationInput = config.publicKey ?? config.accessSecret;

  const getAccessSigningKey = createKeyResolver(
    accessSigningInput,
    config.algorithm,
    "sign",
    "[zero-auth] Cannot issue access tokens in verifier-only mode: `privateKey` is missing."
  );

  const getAccessVerificationKey = createKeyResolver(
    accessVerificationInput,
    config.algorithm,
    "verify",
    "[zero-auth] Verification key is missing."
  );

  const refreshAlgorithm: SupportedAlgorithm = config.refreshSecret ? "HS256" : config.algorithm;

  const refreshSigningInput =
    config.refreshPrivateKey ??
    (config.refreshSecret !== undefined ? config.refreshSecret : config.privateKey);

  const refreshVerificationInput =
    config.refreshPublicKey ??
    (config.refreshSecret !== undefined ? config.refreshSecret : config.publicKey);

  const getRefreshSigningKey = createKeyResolver(
    refreshSigningInput,
    refreshAlgorithm,
    "sign",
    "[zero-auth] Cannot issue refresh tokens in verifier-only mode: `privateKey` or `refreshPrivateKey` is missing."
  );

  const getRefreshVerificationKey = createKeyResolver(
    refreshVerificationInput,
    refreshAlgorithm,
    "verify",
    "[zero-auth] Refresh token verification key is missing."
  );

  return {
    async generateAccessToken(payload: JwtPayload): Promise<string> {
      const key = await getAccessSigningKey();
      return signToken(payload, key, config.accessExpiresIn, {
        ...config.jwt,
        algorithm: config.algorithm,
        ...(config.keyId !== undefined && { keyId: config.keyId }),
      });
    },

    async generateRefreshToken(payload: JwtPayload): Promise<string> {
      const key = await getRefreshSigningKey();
      return signToken(payload, key, config.refreshExpiresIn, {
        ...config.jwt,
        algorithm: refreshAlgorithm,
        ...(config.keyId !== undefined && { keyId: config.keyId }),
      });
    },

    async generateTokenPair(payload: JwtPayload): Promise<TokenPair> {
      const [accessToken, refreshToken] = await Promise.all([
        this.generateAccessToken(payload),
        this.generateRefreshToken(payload),
      ]);
      return { accessToken, refreshToken };
    },

    async verifyAccessToken(token: string): Promise<AuthUser> {
      if (jwksResolver) {
        return verifyToken(token, jwksResolver, {
          ...config.jwt,
          ...(config.algorithm ? { algorithm: config.algorithm } : {}),
        });
      }
      const key = await getAccessVerificationKey();
      return verifyToken(token, key, {
        ...config.jwt,
        algorithm: config.algorithm,
      });
    },

    async verifyRefreshToken(token: string): Promise<AuthUser> {
      if (jwksResolver && !config.refreshPublicKey && !config.refreshSecret) {
        return verifyToken(token, jwksResolver, {
          ...config.jwt,
          ...(config.algorithm ? { algorithm: config.algorithm } : {}),
        });
      }
      const key = await getRefreshVerificationKey();
      return verifyToken(token, key, {
        ...config.jwt,
        algorithm: refreshAlgorithm,
      });
    },

    decodeToken(token: string): AuthUser {
      return decodeToken(token);
    },
  };
}
