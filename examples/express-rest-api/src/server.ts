/**
 * @0-auth/zero-auth — Express REST API Example
 *
 * Demonstrates stateless Bearer-token authentication for mobile apps,
 * CLI tools, and SPAs that manage tokens in memory / localStorage.
 *
 * Features shown:
 *   • Login / Register with JSON token pair response
 *   • Protected routes (auth.protect)
 *   • Role-based access control (auth.authorize)
 *   • Optional authentication (auth.optional)
 *   • Stateless token refresh (auth.refreshHandler)
 *   • Token introspection (auth.decodeToken)
 *   • Structured error handling (auth.errorHandler)
 *
 * Run:  npm start            → http://localhost:3000
 * Dev:  npm run dev           → auto-restart on changes
 */

import express from "express";
import { createAuth } from "@0-auth/zero-auth";

// ─── In-Memory User Store (replace with a real DB) ───────────────────────────

interface User {
  id: string;
  email: string;
  password: string; // plain text for demo only — hash in production!
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

  const tokens = await auth.generateTokenPair({
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

  const tokens = await auth.generateTokenPair({
    id: user.id,
    email: user.email,
    role: user.role,
  });

  res.json({ user: { id: user.id, email: user.email, role: user.role }, ...tokens });
});

// ── Public: Refresh ──────────────────────────────────────────────────────────

app.post("/auth/refresh", auth.refreshHandler());

// ── Protected: Profile ───────────────────────────────────────────────────────

app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

// ── Optional Auth: Posts ─────────────────────────────────────────────────────

app.get("/posts", auth.optional(), (req, res) => {
  const posts = [
    { id: 1, title: "Getting Started with zero-auth", public: true },
    { id: 2, title: "Advanced Token Rotation", public: true },
    { id: 3, title: "Your Draft Post", public: false },
  ];

  if (req.user) {
    // Authenticated — show all posts including drafts
    res.json({
      message: `Welcome back, ${req.user.email}!`,
      posts,
    });
  } else {
    // Guest — show only public posts
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

// ── Public: Token Introspection (debugging) ──────────────────────────────────

app.get("/token/inspect", (req, res) => {
  const token = req.query.token as string | undefined;
  if (!token) {
    res.status(400).json({ error: "Provide ?token=<jwt>" });
    return;
  }

  try {
    const decoded = auth.decodeToken(token);
    res.json({ decoded });
  } catch {
    res.status(400).json({ error: "Could not decode token" });
  }
});

// ── Error Handler (must be last) ─────────────────────────────────────────────

app.use(auth.errorHandler);

// ── Start Server ─────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
┌──────────────────────────────────────────────────────┐
│  @0-auth/zero-auth — REST API Example                │
│  Server running on http://localhost:${PORT}              │
│                                                      │
│  Seed users:                                         │
│    admin@example.com / admin123  (role: admin)       │
│    user@example.com  / user123   (role: user)        │
│                                                      │
│  Try:  curl -X POST http://localhost:${PORT}/auth/login │
│        -H "Content-Type: application/json"           │
│        -d '{"email":"admin@example.com",             │
│             "password":"admin123"}'                   │
└──────────────────────────────────────────────────────┘
  `);
});
