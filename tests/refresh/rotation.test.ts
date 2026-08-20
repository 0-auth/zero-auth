import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { createAuth, createInMemoryRevocationStore } from "../../src/index.js";
import { decodeToken } from "../../src/core/decode.js";

describe("Refresh rotation", () => {
  it("rotates refresh tokens and calls revoke hook before issuing", async () => {
    const revoked: string[] = [];
    const store = createInMemoryRevocationStore();

    const auth = createAuth({
      accessSecret: "rotate-access-secret-min-32-chars-xxxxx",
      refreshSecret: "rotate-refresh-secret-min-32-chars-xxxxx",
      accessExpiresIn: "15m",
      refreshExpiresIn: "7d",
      cookies: { options: { secure: false } },
      refreshOptions: {
        rotate: true,
        revokeRefreshToken: async (jti: string, ctx) => {
          revoked.push(jti);
          await store.revoke(jti, ctx?.familyId);
        },
        registerRefreshToken: async (jti, ctx) => {
          await store.register(jti, ctx.familyId);
        },
        isRevoked: (jti) => store.isRevoked(jti),
      },
    });

    const app = express();
    app.use(express.json());

    app.post("/auth/login", async (_req, res) => {
      const tokens = await auth.sendAuthTokens(res, { id: "u1", email: "u@example.com" });
      res.json(tokens);
    });

    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const loginRes = await request(app).post("/auth/login");
    expect(loginRes.status).toBe(200);
    const oldRefresh = loginRes.body.refreshToken as string;
    expect(oldRefresh).toBeDefined();

    const refreshRes = await request(app)
      .post("/auth/refresh")
      .set("Authorization", `Bearer ${oldRefresh}`)
      .send();

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body).toHaveProperty("accessToken");
    expect(refreshRes.body).toHaveProperty("refreshToken");

    expect(revoked.length).toBeGreaterThanOrEqual(1);

    const oldJti = revoked[0]!;
    expect(await store.isRevoked(oldJti)).toBe(true);

    // Old refresh must already be revoked (atomic revoke-before-issue).
    const replay = await request(app)
      .post("/auth/refresh")
      .set("Authorization", `Bearer ${oldRefresh}`)
      .send();
    expect(replay.status).toBe(401);
  });

  it("fails closed when revokeRefreshToken throws", async () => {
    const auth = createAuth({
      accessSecret: "rotate-access-secret-min-32-chars-failc",
      refreshSecret: "rotate-refresh-secret-min-32-chars-failc",
      cookies: { options: { secure: false } },
      refreshOptions: {
        rotate: true,
        isRevoked: async () => false,
        revokeRefreshToken: async () => {
          throw new Error("redis down");
        },
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/login", async (_req, res) => {
      res.json(await auth.sendAuthTokens(res, { id: "u-fail" }));
    });
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const loginRes = await request(app).post("/auth/login");
    const refresh = loginRes.body.refreshToken as string;

    const res = await request(app)
      .post("/auth/refresh")
      .set("Authorization", `Bearer ${refresh}`)
      .send();

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("AUTH_TOKEN_INVALID");
  });

  it("preserves custom claims across refresh", async () => {
    const store = createInMemoryRevocationStore();
    const auth = createAuth({
      accessSecret: "claims-access-secret-min-32-chars-xxxx",
      refreshSecret: "claims-refresh-secret-min-32-chars-xxx",
      cookies: { options: { secure: false } },
      refreshOptions: {
        rotate: true,
        isRevoked: (jti) => store.isRevoked(jti),
        revokeRefreshToken: (jti, ctx) => store.revoke(jti, ctx?.familyId),
        registerRefreshToken: (jti, ctx) => store.register(jti, ctx.familyId),
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/login", async (_req, res) => {
      res.json(
        await auth.sendAuthTokens(res, {
          id: "u-claims",
          email: "c@example.com",
          role: "user",
          tenantId: "tenant-9",
          plan: "pro",
        })
      );
    });
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const loginRes = await request(app).post("/auth/login");
    const refresh = loginRes.body.refreshToken as string;

    const refreshRes = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: refresh });

    expect(refreshRes.status).toBe(200);
    const access = decodeToken(refreshRes.body.accessToken as string);
    expect(access["tenantId"]).toBe("tenant-9");
    expect(access["plan"]).toBe("pro");
    expect(access.email).toBe("c@example.com");
    expect(access["fid"]).toBeTypeOf("string");
  });

  it("prefers refresh cookie over access Bearer header", async () => {
    const auth = createAuth({
      accessSecret: "bearer-access-secret-min-32-chars-xxxx",
      refreshSecret: "bearer-refresh-secret-min-32-chars-xxx",
      cookies: { options: { secure: false } },
      refreshOptions: {
        rotate: false,
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/login", async (_req, res) => {
      res.json(await auth.sendAuthTokens(res, { id: "u-spa", role: "user" }));
    });
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const loginRes = await request(app).post("/auth/login");
    const accessToken = loginRes.body.accessToken as string;
    const refreshToken = loginRes.body.refreshToken as string;

    // SPA pattern: Authorization carries access token; refresh lives in cookie.
    const res = await request(app)
      .post("/auth/refresh")
      .set("Authorization", `Bearer ${accessToken}`)
      .set("Cookie", `refresh_token=${refreshToken}`)
      .send();

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("accessToken");
  });

  it("kills the token family on refresh reuse", async () => {
    const store = createInMemoryRevocationStore();
    const reuseEvents: string[] = [];

    const auth = createAuth({
      accessSecret: "family-access-secret-min-32-chars-xxxx",
      refreshSecret: "family-refresh-secret-min-32-chars-xxx",
      cookies: { options: { secure: false } },
      refreshOptions: {
        rotate: true,
        isRevoked: (jti) => store.isRevoked(jti),
        revokeRefreshToken: (jti, ctx) => store.revoke(jti, ctx?.familyId),
        registerRefreshToken: (jti, ctx) => store.register(jti, ctx.familyId),
        onRefreshReuse: async (ctx) => {
          reuseEvents.push(ctx.jti);
          if (ctx.familyId) await store.revokeFamily(ctx.familyId);
        },
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/login", async (_req, res) => {
      res.json(await auth.sendAuthTokens(res, { id: "u-family" }));
    });
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const loginRes = await request(app).post("/auth/login");
    const r1 = loginRes.body.refreshToken as string;

    const first = await request(app).post("/auth/refresh").send({ refreshToken: r1 });
    expect(first.status).toBe(200);
    const r2 = first.body.refreshToken as string;

    // Replay stolen r1 — should reject and revoke family (including r2).
    const replay = await request(app).post("/auth/refresh").send({ refreshToken: r1 });
    expect(replay.status).toBe(401);
    expect(reuseEvents.length).toBe(1);

    const r2Replay = await request(app).post("/auth/refresh").send({ refreshToken: r2 });
    expect(r2Replay.status).toBe(401);
  });

  it("handles inMemoryRevocationStore TTL expiration and sizing correctly", async () => {
    // Store with 0.05 second TTL
    const shortTtlStore = createInMemoryRevocationStore(0.05);

    await shortTtlStore.revoke("jti-1", "family-1");
    await shortTtlStore.register("jti-2", "family-1");

    expect(shortTtlStore._size()).toBe(1);
    expect(shortTtlStore._familySize("family-1")).toBe(2);
    expect(shortTtlStore._familySize("non-existent")).toBe(0);

    expect(await shortTtlStore.isRevoked("jti-1")).toBe(true);
    expect(await shortTtlStore.isRevoked("unknown-jti")).toBe(false);

    // Revoke unknown family without throwing
    await shortTtlStore.revokeFamily("unknown-family");

    // Wait for TTL to expire
    await new Promise((r) => setTimeout(r, 80));

    // After expiration, isRevoked cleans up map and returns false
    expect(await shortTtlStore.isRevoked("jti-1")).toBe(false);
  });
});
