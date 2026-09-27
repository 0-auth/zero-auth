import express from "express";
import { createAuth, exportPublicKeyToJwk } from "@0-auth/zero-auth";
import { initialKeyPair, initialKeyId, rotatedKeyPair, rotatedKeyId } from "./keys.js";

export interface AuthServerOptions {
  issuer?: string;
  audience?: string;
}

export function createAuthServer(options?: AuthServerOptions) {
  const app = express();
  app.use(express.json());

  const issuer = options?.issuer ?? "http://localhost:4000";
  const audience = options?.audience ?? "microservices-api";

  // State to support dynamic key rotation in the demo
  let isRotated = false;

  let currentAuth = createAuth({
    algorithm: "RS256",
    keyId: initialKeyId,
    privateKey: initialKeyPair.privateKey,
    publicKey: initialKeyPair.publicKey,
    jwt: { issuer, audience },
    accessExpiresIn: "15m",
  });

  // 1. Standard JWKS Endpoint (serving public keys for downstream services)
  app.get("/.well-known/jwks.json", async (req, res, next) => {
    try {
      if (!isRotated) {
        // Use zero-auth's built-in handler when not rotated
        return currentAuth.jwksHandler()(req, res, next);
      }

      // If rotated, serve both keys so old tokens still verify while new tokens use new key
      const [jwk1, jwk2] = await Promise.all([
        exportPublicKeyToJwk(initialKeyPair.publicKey, { kid: initialKeyId, alg: "RS256" }),
        exportPublicKeyToJwk(rotatedKeyPair.publicKey, { kid: rotatedKeyId, alg: "RS256" }),
      ]);

      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
      res.json({ keys: [jwk2, jwk1] });
    } catch (err) {
      next(err);
    }
  });

  // 2. Demo Login Endpoint (signs tokens with active RS256 private key)
  app.post("/auth/login", async (req, res, next) => {
    try {
      const { email, password } = req.body ?? {};

      if (email === "admin@example.com" && password === "admin123") {
        const tokenPair = await currentAuth.generateTokenPair({
          id: "user-1",
          email: "admin@example.com",
          role: "admin",
        });
        return res.json({
          user: { id: "user-1", email: "admin@example.com", role: "admin" },
          ...tokenPair,
        });
      }

      if (email === "user@example.com" && password === "user123") {
        const tokenPair = await currentAuth.generateTokenPair({
          id: "user-2",
          email: "user@example.com",
          role: "member",
        });
        return res.json({
          user: { id: "user-2", email: "user@example.com", role: "member" },
          ...tokenPair,
        });
      }

      return res.status(401).json({ error: "Invalid credentials" });
    } catch (err) {
      next(err);
    }
  });

  // 3. Demo Endpoint: Rotate Key Pair (demonstrates zero-downtime key rotation)
  app.post("/auth/rotate-keys", async (_req, res, next) => {
    try {
      isRotated = true;
      currentAuth = createAuth({
        algorithm: "RS256",
        keyId: rotatedKeyId,
        privateKey: rotatedKeyPair.privateKey,
        publicKey: rotatedKeyPair.publicKey,
        jwt: { issuer, audience },
        accessExpiresIn: "15m",
      });

      // Issue a sample token signed with the newly active rotated key
      const sampleToken = await currentAuth.generateAccessToken({
        id: "user-rotated",
        email: "alice@example.com",
        role: "admin",
      });

      res.json({
        message: "Auth server successfully rotated signing keys to " + rotatedKeyId,
        activeKeyId: rotatedKeyId,
        sampleToken,
      });
    } catch (err) {
      next(err);
    }
  });

  app.use(currentAuth.errorHandler);

  return app;
}

// Standalone execution
if (process.env["NODE_ENV"] !== "test") {
  const port = process.env["AUTH_PORT"] ?? 4000;
  const app = createAuthServer({
    issuer: `http://localhost:${port}`,
    audience: "microservices-api",
  });
  app.listen(port, () => {
    console.log(`🔐 Central Auth Server listening on http://localhost:${port}`);
    console.log(`   JWKS endpoint: http://localhost:${port}/.well-known/jwks.json`);
  });
}
