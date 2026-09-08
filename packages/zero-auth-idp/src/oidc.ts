import { createPublicKey, generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import type { IdentityUser, OidcConfig } from "./types.js";

const DEFAULT_ID_TOKEN_TTL_SECONDS = 5 * 60;

function positiveInteger(value: number | undefined, fallback: number): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved <= 0) {
    throw new RangeError("oidc.idTokenTtlSeconds must be a positive integer.");
  }
  return resolved;
}

export interface OidcRuntime {
  publicJwk: Record<string, unknown>;
  signIdToken(input: {
    clientId: string;
    user: IdentityUser;
    nonce: string;
    authTime: number;
  }): Promise<string>;
}

export function createOidcRuntime(issuer: string, config: OidcConfig): OidcRuntime {
  let privateKey: KeyObject;
  let publicKey: KeyObject;
  if (config.signingKey) {
    privateKey = config.signingKey;
    publicKey = createPublicKey(config.signingKey);
  } else {
    if (process.env["NODE_ENV"] === "production") {
      throw new Error("oidc.signingKey is required in production.");
    }
    const generated = generateKeyPairSync("rsa", { modulusLength: 2048 });
    privateKey = generated.privateKey;
    publicKey = generated.publicKey;
  }

  const keyId = config.keyId ?? `zero-auth-${randomUUID()}`;
  if (!keyId || keyId.length > 128) throw new Error("oidc.keyId must be 1-128 characters.");
  const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  publicJwk["kid"] = keyId;
  publicJwk["use"] = "sig";
  publicJwk["alg"] = "RS256";
  const idTokenTtlSeconds = positiveInteger(config.idTokenTtlSeconds, DEFAULT_ID_TOKEN_TTL_SECONDS);
  if (publicKey.asymmetricKeyType !== "rsa") {
    throw new Error("oidc.signingKey must be an RSA key.");
  }

  return {
    publicJwk,
    signIdToken: async ({ clientId, user, nonce, authTime }) => {
      const issuedAt = Math.floor(Date.now() / 1000);
      const payload = {
        ...(user.email ? { email: user.email } : {}),
        ...(user.name ? { name: user.name } : {}),
        auth_time: Math.floor(authTime / 1000),
        nonce,
      };
      return new SignJWT(payload)
        .setProtectedHeader({ alg: "RS256", kid: keyId, typ: "JWT" })
        .setIssuer(issuer)
        .setSubject(user.id)
        .setAudience(clientId)
        .setIssuedAt(issuedAt)
        .setExpirationTime(issuedAt + idTokenTtlSeconds)
        .sign(privateKey);
    },
  };
}
