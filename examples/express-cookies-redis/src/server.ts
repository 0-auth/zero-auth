/**
 * @0-auth/zero-auth — Cookie Auth + Redis Rotation Example
 *
 * Demonstrates HTTP-only cookie authentication with refresh token
 * rotation backed by a Redis revocation store. When a rotated refresh
 * token is replayed (stolen), the entire token family is revoked.
 *
 * Features shown:
 *   • Cookie-based auth (auth.sendAuthTokens / auth.clearAuth)
 *   • Refresh token rotation (rotate: true)
 *   • Redis-backed atomic refresh-token consumption
 *   • Token family revocation on reuse detection (onRefreshReuse)
 *   • Protected routes, RBAC, optional auth
 *   • Structured error handling
 *
 * Prerequisites:
 *   1. Redis running (docker compose up -d)
 *   2. cp .env.example .env  (and set secrets)
 *
 * Run:  npm start            → http://localhost:3001
 * Dev:  npm run dev           → auto-restart on changes
 */

import "dotenv/config";
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import express from "express";
import { Redis } from "ioredis";
import { createAuth } from "@0-auth/zero-auth";
import { createRedisRevocationStore } from "./store.js";

const scrypt = promisify(scryptCallback);
const isProduction = process.env["NODE_ENV"] === "production";
const redisUrl = process.env["REDIS_URL"] ?? "redis://localhost:6379";

if (isProduction) {
  const missing = [
    !process.env["JWT_ACCESS_SECRET"] && "JWT_ACCESS_SECRET",
    !process.env["JWT_REFRESH_SECRET"] && "JWT_REFRESH_SECRET",
    !process.env["REDIS_URL"] && "REDIS_URL",
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(`Missing production environment variables: ${missing.join(", ")}`);
  }
}

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const key = (await scrypt(password, salt, 64)) as Buffer;
  return `${salt}:${key.toString("hex")}`;
}

async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [salt, keyHex] = storedHash.split(":");
  if (!salt || !keyHex) return false;

  const expected = Buffer.from(keyHex, "hex");
  const actual = (await scrypt(password, salt, expected.length)) as Buffer;
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// ─── Redis ───────────────────────────────────────────────────────────────────

const redis = new Redis(redisUrl);
const store = createRedisRevocationStore(redis);

redis.on("connect", () => console.log("✅ Connected to Redis"));
redis.on("error", (err) => console.error("❌ Redis error:", err.message));

// ─── In-Memory User Store (replace with a real DB) ───────────────────────────

interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: string;
}

const users: User[] = [
  {
    id: "1",
    email: "admin@example.com",
    passwordHash: await hashPassword("admin123"),
    role: "admin",
  },
  {
    id: "2",
    email: "user@example.com",
    passwordHash: await hashPassword("user123"),
    role: "user",
  },
];

let nextId = 3;

// ─── Auth Instance ───────────────────────────────────────────────────────────

const auth = createAuth({
  accessSecret: process.env["JWT_ACCESS_SECRET"] || "dev-access-secret-at-least-32-characters!!",
  refreshSecret: process.env["JWT_REFRESH_SECRET"] || "dev-refresh-secret-at-least-32-characters!",
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",

  // ── Cookie Config ──────────────────────────────────────────────────────────
  cookies: {
    accessTokenName: "access_token",
    refreshTokenName: "refresh_token",
    options: {
      secure: isProduction,
      sameSite: "lax",
      path: "/",
    },
  },

  // ── Refresh Token Rotation with Redis ──────────────────────────────────────
  refreshOptions: {
    rotate: true,

    // Redis SET NX makes each refresh token single-use across instances.
    consumeRefreshToken: (oldJti, ctx) => store.consume(oldJti, ctx?.familyId),

    // Called after issuing new tokens — track the new jti under its family.
    registerRefreshToken: (newJti, ctx) => store.register(newJti, ctx.familyId),

    // Called when a revoked token is replayed — kill the entire family.
    onRefreshReuse: async (ctx) => {
      console.warn(
        `🚨 Refresh token reuse detected! user=${ctx.userId} jti=${ctx.jti} family=${ctx.familyId}`
      );
      if (ctx.familyId) {
        await store.revokeFamily(ctx.familyId);
      }
    },
  },
});

// ─── Express App ─────────────────────────────────────────────────────────────

const app = express();
app.disable("x-powered-by");
if (isProduction) app.set("trust proxy", 1);
app.use(express.json());

app.get("/healthz", async (_req, res) => {
  try {
    await redis.ping();
    res.json({ status: "ok", redis: "ok" });
  } catch {
    res.status(503).json({ status: "unhealthy", redis: "unavailable" });
  }
});

// ── Public: Register ─────────────────────────────────────────────────────────

app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body as {
    email?: string;
    password?: string;
  };

  if (!email || !password) {
    res.status(400).json({ error: "email and password are required" });
    return;
  }

  if (users.find((u) => u.email === email)) {
    res.status(409).json({ error: "Email already registered" });
    return;
  }

  const user: User = {
    id: String(nextId++),
    email,
    passwordHash: await hashPassword(password),
    role: "user",
  };
  users.push(user);

  // sendAuthTokens sets HTTP-only cookies AND returns the tokens as JSON
  const tokens = await auth.sendAuthTokens(res, {
    id: user.id,
    email: user.email,
    role: user.role,
  });

  res.status(201).json({ user: { id: user.id, email, role: user.role }, ...tokens });
});

// ── Public: Login ────────────────────────────────────────────────────────────

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body as {
    email?: string;
    password?: string;
  };

  const user = users.find((u) => u.email === email);
  if (!user || !(await verifyPassword(password || "", user.passwordHash))) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const tokens = await auth.sendAuthTokens(res, {
    id: user.id,
    email: user.email,
    role: user.role,
  });

  res.json({ user: { id: user.id, email: user.email, role: user.role }, ...tokens });
});

// ── Public: Logout ───────────────────────────────────────────────────────────

app.post("/auth/logout", (_req, res) => {
  auth.clearAuth(res);
  res.json({ message: "Logged out" });
});

// ── Public: Refresh (cookies auto-update on rotation) ────────────────────────

app.post("/auth/refresh", auth.refreshHandler());

// ── Protected: Profile ───────────────────────────────────────────────────────

app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

// ── Optional Auth: Posts ─────────────────────────────────────────────────────

app.get("/posts", auth.optional(), (req, res) => {
  const posts = [
    { id: 1, title: "Getting Started with zero-auth", public: true },
    { id: 2, title: "Cookie Security Best Practices", public: true },
    { id: 3, title: "Your Draft Post", public: false },
  ];

  if (req.user) {
    res.json({ message: `Welcome back, ${req.user.email}!`, posts });
  } else {
    res.json({
      message: "Browsing as guest",
      posts: posts.filter((p) => p.public),
    });
  }
});

// ── Protected + RBAC: Admin Delete User ──────────────────────────────────────

app.delete("/admin/users/:id", auth.protect(), auth.authorize(["admin"]), (req, res) => {
  const targetId = req.params.id;
  const idx = users.findIndex((u) => u.id === targetId);

  if (idx === -1) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  users.splice(idx, 1);
  res.json({ message: `User ${targetId} deleted`, deletedBy: req.user!.id });
});

// ── Error Handler (must be last) ─────────────────────────────────────────────

app.use(auth.errorHandler);

// ── Export for testing ────────────────────────────────────────────────────────

export { app, auth, store, redis };

// ── Start Server ─────────────────────────────────────────────────────────────

if (process.env["NODE_ENV"] !== "test") {
  const PORT = Number(process.env["PORT"] || 3001);
  const server = app.listen(PORT, () => {
    console.log(`
┌──────────────────────────────────────────────────────────────┐
│  @0-auth/zero-auth — Cookie + Redis Rotation Example         │
│  Server running on http://localhost:${PORT}                      │
│                                                              │
│  Seed users:                                                 │
│    admin@example.com / admin123  (role: admin)               │
│    user@example.com  / user123   (role: user)                │
│                                                              │
│  Features:                                                   │
│    ✓ HTTP-only cookie auth                                   │
│    ✓ Refresh token rotation                                  │
│    ✓ Redis-backed family revocation                          │
│    ✓ Reuse detection                                         │
│                                                              │
│  Try:  curl -X POST http://localhost:${PORT}/auth/login          │
│        -H "Content-Type: application/json" -c cookies.txt    │
│        -d '{"email":"admin@example.com",                     │
│             "password":"admin123"}'                           │
└──────────────────────────────────────────────────────────────┘
    `);
  });

  const shutdown = (signal: string) => {
    console.log(`${signal} received; shutting down`);
    server.close(async () => {
      await redis.quit().catch(() => redis.disconnect());
      process.exit(0);
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
