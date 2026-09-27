import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { decodeProtectedHeader } from "jose";
import express from "express";
import request from "supertest";
import {
  createAuth,
  signToken,
  verifyToken,
  isAsymmetricAlgorithm,
  isSymmetricAlgorithm,
  SYMMETRIC_ALGORITHMS,
  ASYMMETRIC_ALGORITHMS,
  AuthError,
} from "../../src/index.js";

// Generate test keys once
const rsaKeys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const ecKeys = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const edKeys = generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const anotherEcKeys = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

describe("Asymmetric Algorithm Classification", () => {
  it("correctly identifies symmetric vs asymmetric algorithms", () => {
    expect(SYMMETRIC_ALGORITHMS).toContain("HS256");
    expect(ASYMMETRIC_ALGORITHMS).toContain("RS256");
    expect(ASYMMETRIC_ALGORITHMS).toContain("ES256");

    expect(isSymmetricAlgorithm("HS256")).toBe(true);
    expect(isSymmetricAlgorithm("HS384")).toBe(true);
    expect(isSymmetricAlgorithm("HS512")).toBe(true);
    expect(isSymmetricAlgorithm("RS256")).toBe(false);

    expect(isAsymmetricAlgorithm("RS256")).toBe(true);
    expect(isAsymmetricAlgorithm("PS256")).toBe(true);
    expect(isAsymmetricAlgorithm("ES256")).toBe(true);
    expect(isAsymmetricAlgorithm("EdDSA")).toBe(true);
    expect(isAsymmetricAlgorithm("HS256")).toBe(false);
  });
});

describe("signToken and verifyToken with Asymmetric Keys", () => {
  it("signs and verifies with RS256", async () => {
    const payload = { id: "user-rsa", role: "admin" };
    const token = await signToken(payload, rsaKeys.privateKey, "15m", {
      algorithm: "RS256",
      keyId: "rsa-key-1",
    });

    const header = decodeProtectedHeader(token);
    expect(header.alg).toBe("RS256");
    expect(header.kid).toBe("rsa-key-1");

    const verified = await verifyToken(token, rsaKeys.publicKey, {
      algorithm: "RS256",
    });
    expect(verified.id).toBe("user-rsa");
    expect(verified.role).toBe("admin");
  });

  it("signs and verifies with ES256 (NIST P-256)", async () => {
    const payload = { id: "user-ec", role: "editor" };
    const token = await signToken(payload, ecKeys.privateKey, "10m", {
      algorithm: "ES256",
    });

    const header = decodeProtectedHeader(token);
    expect(header.alg).toBe("ES256");

    const verified = await verifyToken(token, ecKeys.publicKey, {
      algorithm: "ES256",
    });
    expect(verified.id).toBe("user-ec");
    expect(verified.role).toBe("editor");
  });

  it("signs and verifies with EdDSA (Ed25519)", async () => {
    const payload = { id: "user-ed", role: "member" };
    const token = await signToken(payload, edKeys.privateKey, "30m", {
      algorithm: "EdDSA",
    });

    const header = decodeProtectedHeader(token);
    expect(header.alg).toBe("EdDSA");

    const verified = await verifyToken(token, edKeys.publicKey, {
      algorithm: "EdDSA",
    });
    expect(verified.id).toBe("user-ed");
    expect(verified.role).toBe("member");
  });

  it("rejects token verified with wrong public key", async () => {
    const token = await signToken({ id: "user-ec" }, ecKeys.privateKey, "15m", {
      algorithm: "ES256",
    });

    await expect(
      verifyToken(token, anotherEcKeys.publicKey, { algorithm: "ES256" })
    ).rejects.toThrow(AuthError);
  });

  it("prevents algorithm confusion attacks (HS256 token rejected by RS256 verifier)", async () => {
    const token = await signToken(
      { id: "attacker" },
      rsaKeys.publicKey, // attacker tries to sign with public key as HMAC secret
      "15m",
      { algorithm: "HS256" }
    );

    await expect(verifyToken(token, rsaKeys.publicKey, { algorithm: "RS256" })).rejects.toThrow(
      AuthError
    );
  });
});

describe("createAuth with Full Asymmetric Configuration", () => {
  it("issues and verifies token pairs using ES256", async () => {
    const auth = createAuth({
      algorithm: "ES256",
      privateKey: ecKeys.privateKey,
      publicKey: ecKeys.publicKey,
      keyId: "ec-key-1",
    });

    expect(auth.config.isAsymmetric).toBe(true);
    expect(auth.config.isVerifierOnly).toBe(false);
    expect(auth.config.algorithm).toBe("ES256");

    const { accessToken, refreshToken } = await auth.generateTokenPair({
      id: "u-full-auth",
      email: "user@example.com",
    });

    const accessHeader = decodeProtectedHeader(accessToken);
    expect(accessHeader.alg).toBe("ES256");
    expect(accessHeader.kid).toBe("ec-key-1");

    const verifiedAccess = await auth.verifyToken(accessToken);
    expect(verifiedAccess.id).toBe("u-full-auth");
    expect(verifiedAccess.email).toBe("user@example.com");

    const verifiedRefresh = await auth.verifyRefreshToken(refreshToken);
    expect(verifiedRefresh.id).toBe("u-full-auth");
  });

  it("protects Express routes with asymmetric tokens", async () => {
    const auth = createAuth({
      algorithm: "RS256",
      privateKey: rsaKeys.privateKey,
      publicKey: rsaKeys.publicKey,
    });

    const app = express();
    app.get("/protected", auth.protect(), (req, res) => {
      res.json({ userId: req.user?.id });
    });
    app.use(auth.errorHandler);

    const token = await auth.generateAccessToken({ id: "user-in-express" });

    const res = await request(app).get("/protected").set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.userId).toBe("user-in-express");
  });
});

describe("createAuth in Verifier-Only Mode (Microservices)", () => {
  it("initializes in verifier-only mode and verifies tokens", async () => {
    // Auth service signs the token
    const issuerAuth = createAuth({
      algorithm: "ES256",
      privateKey: ecKeys.privateKey,
      publicKey: ecKeys.publicKey,
    });
    const token = await issuerAuth.generateAccessToken({
      id: "microservice-user",
      role: "admin",
    });

    // Downstream service has only public key
    const verifierAuth = createAuth({
      algorithm: "ES256",
      publicKey: ecKeys.publicKey,
    });

    expect(verifierAuth.config.isVerifierOnly).toBe(true);
    expect(verifierAuth.config.isAsymmetric).toBe(true);

    const user = await verifierAuth.verifyToken(token);
    expect(user.id).toBe("microservice-user");
    expect(user.role).toBe("admin");

    // Express route in downstream service
    const app = express();
    app.get(
      "/service/data",
      verifierAuth.protect(),
      verifierAuth.authorize(["admin"]),
      (req, res) => {
        res.json({ success: true, user: req.user });
      }
    );
    app.use(verifierAuth.errorHandler);

    const res = await request(app).get("/service/data").set("Authorization", `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe("microservice-user");
  });

  it("throws descriptive error when attempting to sign in verifier-only mode", async () => {
    const verifierAuth = createAuth({
      algorithm: "ES256",
      publicKey: ecKeys.publicKey,
    });

    await expect(verifierAuth.generateAccessToken({ id: "test" })).rejects.toThrow(
      "[zero-auth] Cannot issue access tokens in verifier-only mode"
    );

    await expect(verifierAuth.generateRefreshToken({ id: "test" })).rejects.toThrow(
      "[zero-auth] Cannot issue refresh tokens in verifier-only mode"
    );

    await expect(verifierAuth.generateTokenPair({ id: "test" })).rejects.toThrow(
      "[zero-auth] Cannot issue access tokens in verifier-only mode"
    );
  });
});

describe("Hybrid Mode (Asymmetric Access + Symmetric Refresh)", () => {
  it("supports asymmetric access tokens with symmetric refresh secret", async () => {
    const auth = createAuth({
      algorithm: "ES256",
      privateKey: ecKeys.privateKey,
      publicKey: ecKeys.publicKey,
      refreshSecret: "refresh-secret-min-32-chars-long-abc!",
    });

    const tokens = await auth.generateTokenPair({ id: "hybrid-user" });

    // Access token is ES256
    expect(decodeProtectedHeader(tokens.accessToken).alg).toBe("ES256");
    const verifiedAccess = await auth.verifyToken(tokens.accessToken);
    expect(verifiedAccess.id).toBe("hybrid-user");

    // Refresh token is HS256
    expect(decodeProtectedHeader(tokens.refreshToken).alg).toBe("HS256");
    const verifiedRefresh = await auth.verifyRefreshToken(tokens.refreshToken);
    expect(verifiedRefresh.id).toBe("hybrid-user");
  });
});

describe("CSRF Support with Asymmetric Auth", () => {
  it("uses csrfSecret for CSRF cookie creation and validation", async () => {
    const auth = createAuth({
      algorithm: "RS256",
      privateKey: rsaKeys.privateKey,
      publicKey: rsaKeys.publicKey,
      csrfSecret: "csrf-symmetric-secret-min-32-chars-abc!",
    });

    const app = express();
    app.use(auth.csrf());

    app.get("/csrf", (req, res) => {
      res.json({ token: auth.csrfToken(res) });
    });

    app.post("/action", (req, res) => {
      res.json({ success: true });
    });
    app.use(auth.errorHandler);

    // Fetch CSRF token
    const csrfRes = await request(app).get("/csrf");
    expect(csrfRes.status).toBe(200);
    const csrfToken = csrfRes.body.token;

    // Call POST with auth cookie and csrf token header
    const postRes = await request(app)
      .post("/action")
      .set("Cookie", [`access_token=dummy`, `csrf_token=${csrfToken}`])
      .set("x-csrf-token", csrfToken);

    expect(postRes.status).toBe(200);
  });

  it("throws error when auth.csrf() is used in asymmetric mode without csrfSecret", () => {
    const auth = createAuth({
      algorithm: "RS256",
      publicKey: rsaKeys.publicKey,
    });

    expect(() => auth.csrf()).toThrow(
      "[zero-auth] CSRF protection requires a symmetric secret. Provide `csrfSecret` or `accessSecret` in AuthConfig."
    );
  });
});

describe("Configuration Validation for Asymmetric Keys", () => {
  it("throws if asymmetric algorithm has no publicKey or privateKey", () => {
    expect(() => {
      createAuth({
        algorithm: "RS256",
      } as unknown as Parameters<typeof createAuth>[0]);
    }).toThrow("Algorithm \"RS256\" is asymmetric and requires at least 'publicKey'");
  });

  it("throws if privateKey is provided without publicKey", () => {
    expect(() => {
      createAuth({
        algorithm: "ES256",
        privateKey: ecKeys.privateKey,
      } as unknown as Parameters<typeof createAuth>[0]);
    }).toThrow("'publicKey' is required when 'privateKey' is provided");
  });

  it("throws if unsupported algorithm is specified", () => {
    expect(() => {
      createAuth({
        algorithm: "UNSUPPORTED_ALG" as unknown as Parameters<typeof createAuth>[0]["algorithm"],
        accessSecret: "secret-at-least-32-chars-long-123456",
        refreshSecret: "secret-at-least-32-chars-long-1234567",
      });
    }).toThrow('Unsupported algorithm: "UNSUPPORTED_ALG"');
  });
});
