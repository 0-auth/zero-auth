import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import {
  createAuth,
  signToken,
  verifyToken,
  createJwksResolver,
  exportPublicKeyToJwk,
  AuthError,
} from "../../src/index.js";

// Generate test keys
const rsaKeys1 = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const rsaKeys2 = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const ecKeys = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

describe("JWKS Configuration & Validation", () => {
  it("rejects invalid jwksUri string", () => {
    expect(() =>
      createAuth({
        jwksUri: "not-a-valid-url",
      })
    ).toThrow("[zero-auth] 'jwksUri' must be a valid HTTP or HTTPS URL");
  });

  it("rejects non-HTTP/HTTPS protocol", () => {
    expect(() =>
      createAuth({
        jwksUri: "ftp://example.com/jwks.json",
      })
    ).toThrow("[zero-auth] 'jwksUri' must have http: or https: protocol");
  });

  it("rejects jwksUri combined with privateKey", () => {
    expect(() =>
      createAuth({
        jwksUri: "https://auth.example.com/.well-known/jwks.json",
        privateKey: rsaKeys1.privateKey,
      })
    ).toThrow(
      "[zero-auth] 'jwksUri' cannot be combined with 'privateKey' or 'accessSecret'. Remote JWKS is a verifier-only mode."
    );
  });

  it("rejects jwksUri combined with accessSecret", () => {
    expect(() =>
      createAuth({
        jwksUri: "https://auth.example.com/.well-known/jwks.json",
        accessSecret: "secret-key-that-is-at-least-32-chars-long",
      })
    ).toThrow(
      "[zero-auth] 'jwksUri' cannot be combined with 'privateKey' or 'accessSecret'. Remote JWKS is a verifier-only mode."
    );
  });

  it("rejects jwksUri combined with publicKey", () => {
    expect(() =>
      createAuth({
        jwksUri: "https://auth.example.com/.well-known/jwks.json",
        publicKey: rsaKeys1.publicKey,
      })
    ).toThrow(
      "[zero-auth] 'jwksUri' cannot be combined with 'publicKey'. Verification keys are fetched dynamically from the JWKS endpoint."
    );
  });

  it("defaults algorithm to RS256 and sets verifier/jwks flags", () => {
    const auth = createAuth({
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
    });

    expect(auth.config.isJwks).toBe(true);
    expect(auth.config.isVerifierOnly).toBe(true);
    expect(auth.config.isAsymmetric).toBe(true);
    expect(auth.config.algorithm).toBe("RS256");
    expect(auth.config.jwksUri).toBe("https://auth.example.com/.well-known/jwks.json");
  });

  it("accepts a URL object as jwksUri", () => {
    const url = new URL("https://auth.example.com/.well-known/jwks.json");
    const auth = createAuth({
      jwksUri: url,
    });

    expect(auth.config.jwksUri).toBe("https://auth.example.com/.well-known/jwks.json");
  });

  it("throws when calling generateAccessToken in JWKS mode", async () => {
    const auth = createAuth({
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
    });

    await expect(auth.generateAccessToken({ id: "user-123" })).rejects.toThrow(
      "[zero-auth] Cannot issue access tokens in verifier-only mode"
    );
  });
});

describe("JWKS Utilities (exportPublicKeyToJwk & getJwks)", () => {
  it("exports RSA public key to valid JWK format with kid and alg", async () => {
    const jwk = await exportPublicKeyToJwk(rsaKeys1.publicKey, {
      kid: "rsa-key-1",
      alg: "RS256",
    });

    expect(jwk.kty).toBe("RSA");
    expect(jwk.use).toBe("sig");
    expect(jwk.kid).toBe("rsa-key-1");
    expect(jwk.alg).toBe("RS256");
    expect(typeof jwk.n).toBe("string");
    expect(typeof jwk.e).toBe("string");
  });

  it("exports EC public key to valid JWK format", async () => {
    const jwk = await exportPublicKeyToJwk(ecKeys.publicKey, {
      kid: "ec-key-1",
      alg: "ES256",
    });

    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.use).toBe("sig");
    expect(jwk.kid).toBe("ec-key-1");
    expect(jwk.alg).toBe("ES256");
    expect(typeof jwk.x).toBe("string");
    expect(typeof jwk.y).toBe("string");
  });

  it("auth.getJwks() returns formatted JWKS and caches result", async () => {
    const auth = createAuth({
      algorithm: "RS256",
      keyId: "server-key-1",
      publicKey: rsaKeys1.publicKey,
      privateKey: rsaKeys1.privateKey,
    });

    const jwks1 = await auth.getJwks();
    expect(jwks1.keys).toHaveLength(1);
    expect(jwks1.keys[0]?.["kid"]).toBe("server-key-1");
    expect(jwks1.keys[0]?.["alg"]).toBe("RS256");
    expect(jwks1.keys[0]?.["kty"]).toBe("RSA");

    const jwks2 = await auth.getJwks();
    expect(jwks1).toBe(jwks2); // cached reference equality
  });

  it("auth.getJwks() throws error when configured with symmetric keys", async () => {
    const auth = createAuth({
      accessSecret: "secret-key-that-is-at-least-32-chars-long",
      refreshSecret: "different-refresh-secret-at-least-32-chars-long",
    });

    await expect(auth.getJwks()).rejects.toThrow(
      "[zero-auth] getJwks() is only available when asymmetric keys ('publicKey') are configured."
    );
  });

  it("auth.getJwks() throws error in remote jwksUri mode", async () => {
    const auth = createAuth({
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
    });

    await expect(auth.getJwks()).rejects.toThrow(
      "[zero-auth] getJwks() is only available when asymmetric keys ('publicKey') are configured."
    );
  });

  it("auth.jwksHandler() serves JWKS endpoint with correct headers", async () => {
    const auth = createAuth({
      algorithm: "RS256",
      keyId: "server-key-1",
      publicKey: rsaKeys1.publicKey,
      privateKey: rsaKeys1.privateKey,
    });

    const app = express();
    app.get("/.well-known/jwks.json", auth.jwksHandler());

    const res = await request(app).get("/.well-known/jwks.json");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.headers["cache-control"]).toBe("public, max-age=3600, stale-while-revalidate=86400");
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0].kid).toBe("server-key-1");
  });
});

describe("Dynamic Remote JWKS Verification with HTTP Mock Server", () => {
  let mockServer: http.Server;
  let jwksUrl: string;
  let currentJwks: { keys: Record<string, unknown>[] };

  beforeAll(async () => {
    // Prepare initial JWKS with rsaKeys1
    const jwk1 = await exportPublicKeyToJwk(rsaKeys1.publicKey, {
      kid: "key-1",
      alg: "RS256",
    });
    currentJwks = { keys: [jwk1 as unknown as Record<string, unknown>] };

    // Start HTTP server serving the mock JWKS
    await new Promise<void>((resolve) => {
      mockServer = http.createServer((req, res) => {
        if (req.url === "/.well-known/jwks.json") {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
          });
          res.end(JSON.stringify(currentJwks));
          return;
        }
        res.writeHead(404);
        res.end("Not Found");
      });

      mockServer.listen(0, "127.0.0.1", () => {
        const address = mockServer.address() as AddressInfo;
        jwksUrl = `http://127.0.0.1:${address.port}/.well-known/jwks.json`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      mockServer.close(() => resolve());
    });
  });

  it("verifies tokens signed by the remote key", async () => {
    const auth = createAuth({
      jwksUri: jwksUrl,
      // Minimal cooldown to make rotation fast in tests
      jwks: { cooldownDuration: 50 },
    });

    const token = await signToken(
      { id: "user-remote-1", role: "admin", email: "alice@example.com" },
      rsaKeys1.privateKey,
      "15m",
      { algorithm: "RS256", keyId: "key-1" }
    );

    const verified = await auth.verifyToken(token);
    expect(verified.id).toBe("user-remote-1");
    expect(verified.role).toBe("admin");
    expect(verified["email"]).toBe("alice@example.com");
  });

  it("protects Express route using remote JWKS token", async () => {
    const auth = createAuth({
      jwksUri: jwksUrl,
    });

    const app = express();
    app.get("/protected", auth.protect(), (req, res) => {
      res.json({ user: req.user });
    });
    app.use(auth.errorHandler);

    const token = await signToken(
      { id: "user-protected", role: "member" },
      rsaKeys1.privateKey,
      "15m",
      { algorithm: "RS256", keyId: "key-1" }
    );

    const res = await request(app).get("/protected").set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe("user-protected");
    expect(res.body.user.role).toBe("member");
  });

  it("dynamically handles key rotation when new key is added to JWKS", async () => {
    const auth = createAuth({
      jwksUri: jwksUrl,
      jwks: { cooldownDuration: 10, cacheMaxAge: 100 },
    });

    // 1. Verify token signed with key-1
    const token1 = await signToken({ id: "user-key-1" }, rsaKeys1.privateKey, "15m", {
      algorithm: "RS256",
      keyId: "key-1",
    });
    const verified1 = await auth.verifyToken(token1);
    expect(verified1.id).toBe("user-key-1");

    // 2. Rotate keys: add rsaKeys2 ("key-2") to the server JWKS
    const jwk2 = await exportPublicKeyToJwk(rsaKeys2.publicKey, {
      kid: "key-2",
      alg: "RS256",
    });
    currentJwks.keys.push(jwk2 as unknown as Record<string, unknown>);

    // Wait a tiny bit for cooldown
    await new Promise((resolve) => setTimeout(resolve, 30));

    // 3. Verify token signed with key-2
    const token2 = await signToken({ id: "user-key-2" }, rsaKeys2.privateKey, "15m", {
      algorithm: "RS256",
      keyId: "key-2",
    });
    const verified2 = await auth.verifyToken(token2);
    expect(verified2.id).toBe("user-key-2");
  });

  it("fails closed when token kid is not in JWKS", async () => {
    const auth = createAuth({
      jwksUri: jwksUrl,
      jwks: { cooldownDuration: 10 },
    });

    const token = await signToken({ id: "user-unknown" }, rsaKeys1.privateKey, "15m", {
      algorithm: "RS256",
      keyId: "unknown-kid",
    });

    await expect(auth.verifyToken(token)).rejects.toThrow(AuthError);
    await expect(auth.verifyToken(token)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("fails closed on signature forgery", async () => {
    const auth = createAuth({
      jwksUri: jwksUrl,
    });

    // Sign with an unannounced key but claiming kid: "key-1"
    const forgedKeys = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const forgedToken = await signToken({ id: "attacker" }, forgedKeys.privateKey, "15m", {
      algorithm: "RS256",
      keyId: "key-1",
    });

    await expect(auth.verifyToken(forgedToken)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("fails closed on expired token", async () => {
    const auth = createAuth({
      jwksUri: jwksUrl,
    });

    const expiredToken = await signToken({ id: "expired-user" }, rsaKeys1.privateKey, "1s", {
      algorithm: "RS256",
      keyId: "key-1",
    });

    // Wait for token to expire
    await new Promise((resolve) => setTimeout(resolve, 1100));

    await expect(auth.verifyToken(expiredToken)).rejects.toMatchObject({
      code: "AUTH_TOKEN_EXPIRED",
    });
  });

  it("fails closed with AUTH_TOKEN_INVALID when JWKS endpoint is unreachable", async () => {
    const unreachableAuth = createAuth({
      jwksUri: "http://127.0.0.1:9999/does-not-exist/jwks.json",
      jwks: { timeoutDuration: 500 },
    });

    const token = await signToken({ id: "user-123" }, rsaKeys1.privateKey, "15m", {
      algorithm: "RS256",
      keyId: "key-1",
    });

    await expect(unreachableAuth.verifyToken(token)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("supports standalone createJwksResolver with verifyToken", async () => {
    const jwksResolver = createJwksResolver(jwksUrl);

    const token = await signToken(
      { id: "user-standalone", role: "operator" },
      rsaKeys1.privateKey,
      "15m",
      { algorithm: "RS256", keyId: "key-1" }
    );

    const verified = await verifyToken(token, jwksResolver);
    expect(verified.id).toBe("user-standalone");
    expect(verified.role).toBe("operator");
  });
});
