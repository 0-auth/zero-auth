import { describe, it, expect, beforeAll } from "vitest";
import express from "express";
import request from "supertest";
import { createAuth } from "../../src/index.js";

// ─── Test App Setup ───────────────────────────────────────────────────────────

const auth = createAuth({
  accessSecret: "integration-access-secret-min-32-chars-ok",
  refreshSecret: "integration-refresh-secret-min-32-chars",
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",
  cookies: {
    options: {
      secure: false, // disable secure for test environment
    },
  },
});

const app = express();
app.use(express.json());

// Simulated user store.
const USERS = {
  "user@example.com": { id: "user-1", email: "user@example.com", role: "user", password: "pass" },
  "admin@example.com": { id: "admin-1", email: "admin@example.com", role: "admin", password: "pass" },
};

// ── Auth Routes ───────────────────────────────────────────────────────────────

app.post("/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body as { email: string; password: string };
    const user = USERS[email as keyof typeof USERS];

    if (!user || user.password !== password) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const tokens = await auth.sendAuthTokens(res, {
      id: user.id,
      email: user.email,
      role: user.role,
    });

    res.json({ message: "Login successful", ...tokens });
  } catch (err) {
    next(err);
  }
});

app.post("/auth/refresh", auth.refreshHandler());

app.post("/auth/logout", (req, res) => {
  auth.clearAuth(res);
  res.json({ message: "Logged out" });
});

// ── Protected Routes ──────────────────────────────────────────────────────────

app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.get("/admin", auth.protect(), auth.authorize(["admin"]), (req, res) => {
  res.json({ message: "Admin area", user: req.user });
});

app.get("/public", auth.optional(), (req, res) => {
  res.json({ authenticated: !!req.user, user: req.user ?? null });
});

// Error handler must be last.
app.use(auth.errorHandler);

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("Express Integration", () => {
  describe("POST /auth/login", () => {
    it("returns tokens for valid credentials", async () => {
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "user@example.com", password: "pass" });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("accessToken");
      expect(res.body).toHaveProperty("refreshToken");
      expect(res.body.message).toBe("Login successful");
    });

    it("sets HTTP-only cookies on login", async () => {
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "user@example.com", password: "pass" });

      const cookies = res.headers["set-cookie"] as string[] | undefined;
      expect(cookies).toBeDefined();
      const cookieStr = cookies?.join("; ") ?? "";
      expect(cookieStr).toContain("access_token=");
      expect(cookieStr).toContain("refresh_token=");
      expect(cookieStr).toContain("HttpOnly");
    });

    it("returns 401 for invalid credentials", async () => {
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "user@example.com", password: "wrong" });

      expect(res.status).toBe(401);
    });
  });

  describe("GET /profile (auth.protect)", () => {
    let accessToken: string;

    beforeAll(async () => {
      const loginRes = await request(app)
        .post("/auth/login")
        .send({ email: "user@example.com", password: "pass" });
      accessToken = (loginRes.body as { accessToken: string }).accessToken;
    });

    it("returns 401 when no token is provided", async () => {
      const res = await request(app).get("/profile");
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("error.code", "AUTH_TOKEN_MISSING");
    });

    it("returns the user for a valid Bearer token", async () => {
      const res = await request(app)
        .get("/profile")
        .set("Authorization", `Bearer ${accessToken}`);

      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({ id: "user-1", email: "user@example.com" });
    });

    it("returns 401 for an invalid token", async () => {
      const res = await request(app)
        .get("/profile")
        .set("Authorization", "Bearer invalid.token");

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("error.code", "AUTH_TOKEN_INVALID");
    });
  });

  describe("GET /admin (auth.authorize)", () => {
    let userToken: string;
    let adminToken: string;

    beforeAll(async () => {
      const [userRes, adminRes] = await Promise.all([
        request(app).post("/auth/login").send({ email: "user@example.com", password: "pass" }),
        request(app).post("/auth/login").send({ email: "admin@example.com", password: "pass" }),
      ]);
      userToken = (userRes.body as { accessToken: string }).accessToken;
      adminToken = (adminRes.body as { accessToken: string }).accessToken;
    });

    it("returns 200 for an admin user", async () => {
      const res = await request(app)
        .get("/admin")
        .set("Authorization", `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Admin area");
    });

    it("returns 403 for a non-admin user", async () => {
      const res = await request(app)
        .get("/admin")
        .set("Authorization", `Bearer ${userToken}`);

      expect(res.status).toBe(403);
      expect(res.body).toHaveProperty("error.code", "AUTH_FORBIDDEN");
    });
  });

  describe("POST /auth/refresh", () => {
    let refreshToken: string;

    beforeAll(async () => {
      const loginRes = await request(app)
        .post("/auth/login")
        .send({ email: "user@example.com", password: "pass" });
      refreshToken = (loginRes.body as { refreshToken: string }).refreshToken;
    });

    it("returns a new access token for a valid refresh token", async () => {
      const res = await request(app)
        .post("/auth/refresh")
        .set("Authorization", `Bearer ${refreshToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("accessToken");
      expect(typeof res.body.accessToken).toBe("string");
    });

    it("returns 401 when no refresh token is provided", async () => {
      const res = await request(app).post("/auth/refresh");
      expect(res.status).toBe(401);
    });

    it("returns 401 for an invalid refresh token", async () => {
      const res = await request(app)
        .post("/auth/refresh")
        .set("Authorization", "Bearer not.a.valid.token");

      expect(res.status).toBe(401);
    });
  });

  describe("GET /public (auth.optional)", () => {
    it("returns authenticated: false when no token is provided", async () => {
      const res = await request(app).get("/public");
      expect(res.status).toBe(200);
      expect(res.body.authenticated).toBe(false);
      expect(res.body.user).toBeNull();
    });

    it("returns authenticated: true with user data when a valid token is provided", async () => {
      const loginRes = await request(app)
        .post("/auth/login")
        .send({ email: "user@example.com", password: "pass" });
      const { accessToken } = loginRes.body as { accessToken: string };

      const res = await request(app)
        .get("/public")
        .set("Authorization", `Bearer ${accessToken}`);

      expect(res.status).toBe(200);
      expect(res.body.authenticated).toBe(true);
      expect(res.body.user).toHaveProperty("id", "user-1");
    });

    it("returns authenticated: false when an invalid token is provided (silent fail)", async () => {
      const res = await request(app)
        .get("/public")
        .set("Authorization", "Bearer broken.token");

      expect(res.status).toBe(200);
      expect(res.body.authenticated).toBe(false);
    });
  });

  describe("POST /auth/logout", () => {
    it("clears auth cookies on logout", async () => {
      const res = await request(app).post("/auth/logout");
      expect(res.status).toBe(200);

      const cookies = res.headers["set-cookie"] as string[] | undefined;
      const cookieStr = cookies?.join("; ") ?? "";
      // Cleared cookies have Max-Age=0 or expires in the past.
      expect(cookieStr).toContain("access_token=");
      expect(cookieStr).toMatch(/Max-Age=0|expires=Thu, 01 Jan 1970/i);
    });
  });
});
