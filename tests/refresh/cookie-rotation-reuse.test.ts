import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { createAuth, createInMemoryRevocationStore } from "../../src/index.js";

describe("Cookie-based rotation and reuse detection", () => {
  it("rotates refresh cookie and rejects reuse when jti is revoked", async () => {
    const store = createInMemoryRevocationStore();
    const revoked: string[] = [];

    const auth = createAuth({
      accessSecret: "cookie-access-secret-min-32-chars-xxxx",
      refreshSecret: "cookie-refresh-secret-min-32-chars-xxxx",
      accessExpiresIn: "15m",
      refreshExpiresIn: "7d",
      cookies: { options: { secure: false } },
      refreshOptions: {
        rotate: true,
        revokeRefreshToken: async (oldJti: string, ctx) => {
          revoked.push(oldJti);
          await store.revoke(oldJti, ctx?.familyId);
        },
        registerRefreshToken: async (jti, ctx) => {
          await store.register(jti, ctx.familyId);
        },
        isRevoked: async (jti: string) => {
          return store.isRevoked(jti);
        },
        onRefreshReuse: async (ctx) => {
          if (ctx.familyId) await store.revokeFamily(ctx.familyId);
        },
      },
    });

    const app = express();
    app.use(express.json());

    app.post("/auth/login", async (_req, res) => {
      const tokens = await auth.sendAuthTokens(res, { id: "u-cookie", email: "c@example.com" });
      res.json(tokens);
    });

    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const loginRes = await request(app).post("/auth/login");
    expect(loginRes.status).toBe(200);
    const oldRefresh = loginRes.body.refreshToken as string;
    expect(oldRefresh).toBeDefined();

    const first = await request(app)
      .post("/auth/refresh")
      .set("Cookie", `refresh_token=${oldRefresh}`)
      .send();

    expect(first.status).toBe(200);
    expect(first.body).toHaveProperty("accessToken");
    expect(first.body).toHaveProperty("refreshToken");

    expect(revoked.length).toBeGreaterThanOrEqual(1);
    const oldJti = revoked[0]!;
    expect(await store.isRevoked(oldJti)).toBe(true);

    const replay = await request(app)
      .post("/auth/refresh")
      .set("Cookie", `refresh_token=${oldRefresh}`)
      .send();

    expect(replay.status).toBe(401);
    expect(replay.body).toHaveProperty("error");
    expect(replay.body.error.code).toBe("AUTH_TOKEN_INVALID");
  });
});
