import {
  importPKCS8,
  importSPKI,
  exportJWK,
  createRemoteJWKSet,
  type KeyLike,
  type JWTVerifyGetKey,
  type JWK,
} from "jose";
import type { SupportedAlgorithm, KeyInput, RemoteJwksConfig } from "../types/auth.js";

export const SYMMETRIC_ALGORITHMS = ["HS256", "HS384", "HS512"] as const;
export const ASYMMETRIC_ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
] as const;

export type SymmetricAlgorithm = (typeof SYMMETRIC_ALGORITHMS)[number];
export type AsymmetricAlgorithm = (typeof ASYMMETRIC_ALGORITHMS)[number];

export function isAsymmetricAlgorithm(alg: string): alg is AsymmetricAlgorithm {
  return (ASYMMETRIC_ALGORITHMS as readonly string[]).includes(alg);
}

export function isSymmetricAlgorithm(alg: string): alg is SymmetricAlgorithm {
  return (SYMMETRIC_ALGORITHMS as readonly string[]).includes(alg);
}

export type ResolvedKey = Uint8Array | KeyLike;
export type VerificationKey = ResolvedKey | JWTVerifyGetKey;

/**
 * Parses and resolves a key for signing or verification.
 */
export async function importKeyInput(
  keyInput: KeyInput,
  alg: SupportedAlgorithm,
  usage: "sign" | "verify"
): Promise<ResolvedKey> {
  if (isSymmetricAlgorithm(alg)) {
    if (typeof keyInput === "string") {
      return new TextEncoder().encode(keyInput);
    }
    if (keyInput instanceof Uint8Array) {
      return keyInput;
    }
    return keyInput as ResolvedKey;
  }

  // Asymmetric algorithm
  if (typeof keyInput === "string") {
    if (usage === "sign") {
      return await importPKCS8(keyInput, alg);
    } else {
      return await importSPKI(keyInput, alg);
    }
  }

  return keyInput as ResolvedKey;
}

/**
 * Creates a cached key resolver function to avoid re-parsing PEM strings.
 */
export function createKeyResolver(
  keyInput: KeyInput | undefined,
  alg: SupportedAlgorithm,
  usage: "sign" | "verify",
  missingMessage?: string
): () => Promise<ResolvedKey> {
  if (!keyInput) {
    return async () => {
      throw new Error(
        missingMessage ??
          `[zero-auth] Key is required for ${usage} operations with algorithm "${alg}".`
      );
    };
  }

  let cachedPromise: Promise<ResolvedKey> | null = null;

  return function getKey(): Promise<ResolvedKey> {
    if (!cachedPromise) {
      cachedPromise = importKeyInput(keyInput, alg, usage);
    }
    return cachedPromise;
  };
}

/**
 * Creates a remote JWKS resolver from a URL string or URL object.
 */
export function createJwksResolver(
  jwksUri: string | URL,
  options?: RemoteJwksConfig
): JWTVerifyGetKey {
  const url = typeof jwksUri === "string" ? new URL(jwksUri) : jwksUri;
  return createRemoteJWKSet(url, {
    ...(options?.cacheMaxAge !== undefined && { cacheMaxAge: options.cacheMaxAge }),
    ...(options?.cooldownDuration !== undefined && { cooldownDuration: options.cooldownDuration }),
    ...(options?.timeoutDuration !== undefined && { timeoutDuration: options.timeoutDuration }),
    ...(options?.headers !== undefined && { headers: options.headers }),
  });
}

/**
 * Exports a public key (PEM string or KeyLike) as a JWK for publication.
 */
export async function exportPublicKeyToJwk(
  publicKeyInput: KeyInput,
  options?: { kid?: string; alg?: string }
): Promise<JWK> {
  const alg = (options?.alg ?? "RS256") as SupportedAlgorithm;
  const key =
    typeof publicKeyInput === "string" ? await importSPKI(publicKeyInput, alg) : publicKeyInput;

  const jwk = await exportJWK(key as KeyLike);
  if (options?.kid !== undefined) jwk.kid = options.kid;
  if (options?.alg !== undefined) jwk.alg = options.alg;
  jwk.use = "sig";
  return jwk;
}
