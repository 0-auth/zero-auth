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
 *   • Redis-backed revocation store (isRevoked, revokeRefreshToken, etc.)
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
import express from "express";
import Redis from "ioredis";
import { createAuth } from "@0-auth/zero-auth";
import { createRedisRevocationStore } from "./store.js";

// ─── Redis ───────────────────────────────────────────────────────────────────

const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
const store = createRedisRevocationStore(redis);

redis.on("connect", () => console.log("✅ Connected to Redis"));
redis.on("error", (err) => console.error("❌ Redis error:", err.message));

// ─── In-Memory User Store (replace with a real DB) ───────────────────────────

interface User {
  id: string;
  email: string;
  password: string;
  role: string;
}

const users: User[] = [
  { id: "1", email: "admin@example.com", password: "admin123", role: "admin" },
  { id: "2", email: "user@example.com", password: "user123", role: "user" },
];

let nextId = 3;

// ─── Auth Instance ───────────────────────────────────────────────────────────

const auth = createAuth({
  accessSecret:
    process.env.JWT_ACCESS_SECRET ||
    "dev-access-secret-at-least-32-characters!!",
  refreshSecret:
    process.env.JWT_REFRESH_SECRET ||
    "dev-refresh-secret-at-least-32-characters!",
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",

  // ── Cookie Config ──────────────────────────────────────────────────────────
  cookies: {
    accessTokenName: "access_token",
    refreshTokenName: "refresh_token",
    options: {
      secure: false, // set true in production (HTTPS)
      sameSite: "lax",
      path: "/",
    },
  },

  // ── Refresh Token Rotation with Redis ──────────────────────────────────────
  refreshOptions: {
    rotate: true,

    // Called before issuing new tokens — revoke the old jti.
    revokeRefreshToken: (oldJti, ctx) =>
      store.revoke(oldJti, ctx?.familyId),

    // Called after issuing new tokens — track the new jti under its family.
    registerRefreshToken: (newJti, ctx) =>
      store.register(newJti, ctx.familyId),

    // Called on every refresh to check if the incoming jti is already revoked.
    isRevoked: (jti) => store.isRevoked(jti),

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
app.use(express.json());

// ── Public: Register ─────────────────────────────────────────────────────────

app.post("/auth/register", async (req, res) => {
  const { email, password, role } = req.body as {
    email?: string;
    password?: string;
    role?: string;
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
    password,
    role: role || "user",
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

  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
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

app.delete(
  "/admin/users/:id",
  auth.protect(),
  auth.authorize(["admin"]),
  (req, res) => {
    const targetId = req.params.id;
    const idx = users.findIndex((u) => u.id === targetId);

    if (idx === -1) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    users.splice(idx, 1);
    res.json({ message: `User ${targetId} deleted`, deletedBy: req.user!.id });
  }
);

// ── Error Handler (must be last) ─────────────────────────────────────────────

app.use(auth.errorHandler);

// ── Start Server ─────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
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
