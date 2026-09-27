import { generateKeyPairSync } from "node:crypto";

/**
 * Generates an RSA 2048-bit key pair encoded as PKCS#8 (private) and SPKI (public) PEMs.
 */
function createRsaKeyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

// Initial key pair used by central auth server
export const initialKeyPair = createRsaKeyPair();
export const initialKeyId = "auth-server-key-2026-v1";

// Rotated key pair for demonstrating zero-downtime key rotation
export const rotatedKeyPair = createRsaKeyPair();
export const rotatedKeyId = "auth-server-key-2026-v2";
