import express from "express";
import { createAuth } from "@0-auth/zero-auth";

export interface ResourceServerOptions {
  jwksUri?: string;
  issuer?: string;
  audience?: string;
}

export function createResourceServer(options?: ResourceServerOptions) {
  const app = express();
  app.use(express.json());

  const jwksUri = options?.jwksUri ?? "http://localhost:4000/.well-known/jwks.json";
  const issuer = options?.issuer ?? "http://localhost:4000";
  const audience = options?.audience ?? "microservices-api";

  // Verifier-Only Mode: Verification keys are fetched dynamically from jwksUri
  const auth = createAuth({
    jwksUri,
    jwt: {
      issuer,
      audience,
      clockTolerance: 5,
    },
    jwks: {
      cacheMaxAge: 600_000,     // 10 minutes in-memory cache
      cooldownDuration: 100,     // 100ms cooldown for responsive rotation in demo/tests
      timeoutDuration: 5_000,   // 5 seconds fetch timeout
    },
  });

  // 1. Public route (no authentication required)
  app.get("/api/public", (_req, res) => {
    res.json({ message: "This is a public endpoint accessible by anyone." });
  });

  // 2. Protected documents route (requires valid JWT verified via remote JWKS)
  app.get("/api/documents", auth.protect(), (req, res) => {
    res.json({
      message: "Access granted via Remote JWKS token verification!",
      user: req.user,
      documents: [
        { id: "doc-1", title: "Quarterly Strategy Report", owner: req.user?.id },
        { id: "doc-2", title: "Microservices Architecture Whitepaper", owner: req.user?.id },
      ],
    });
  });

  // 3. Admin-only route (requires 'admin' role)
  app.get("/api/admin/metrics", auth.protect(), auth.authorize(["admin"]), (req, res) => {
    res.json({
      message: "Admin authorization verified via token claims!",
      user: req.user,
      systemMetrics: {
        activeServices: 12,
        requestsPerSecond: 1840,
        uptime: "99.99%",
      },
    });
  });

  // Error handler mounts after all routes
  app.use(auth.errorHandler);

  return app;
}

// Standalone execution
if (process.env["NODE_ENV"] !== "test") {
  const port = process.env["RESOURCE_PORT"] ?? 4001;
  const authPort = process.env["AUTH_PORT"] ?? 4000;
  const app = createResourceServer({
    jwksUri: `http://localhost:${authPort}/.well-known/jwks.json`,
    issuer: `http://localhost:${authPort}`,
    audience: "microservices-api",
  });
  app.listen(port, () => {
    console.log(`📦 Downstream Resource Service listening on http://localhost:${port}`);
    console.log(`   Verifying tokens against JWKS: http://localhost:${authPort}/.well-known/jwks.json`);
  });
}
