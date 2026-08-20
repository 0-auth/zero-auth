import { describe, it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";
import { createAuth, createInMemoryRevocationStore } from "../../src/index.js";

const ACCESS_SECRET = "test-access-secret-32-chars-long-abc!";
const REFRESH_SECRET = "test-refresh-secret-32-chars-long-xyz!";

describe("Security Audit: Concurrency & Refresh Rotation Hardening", () => {
  it("detects reuse and triggers onRefreshReuse when the same token is refreshed concurrently/sequentially", async () => {
    const store = createInMemoryRevocationStore();
    const onReuseSpy = vi.fn();

    const auth = createAuth({
      accessSecret: ACCESS_SECRET,
      refreshSecret: REFRESH_SECRET,
      refreshOptions: {
        rotate: true,
        isRevoked: (jti) => store.isRevoked(jti),
        revokeRefreshToken: async (jti, ctx) => {
          await store.revoke(jti, ctx?.familyId);
        },
        registerRefreshToken: async (jti, ctx) => {
          await store.register(jti, ctx.familyId);
        },
        onRefreshReuse: async (ctx) => {
          onReuseSpy(ctx);
          if (ctx.familyId) {
            await store.revokeFamily(ctx.familyId);
          }
        },
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    // 1. Issue an initial refresh token
    const tokenPair = await auth.generateTokenPair({ id: "user-victim", tenantId: "tenant-1" });
    const initialRefreshToken = tokenPair.refreshToken;

    // 2. Legitimate user refreshes token
    const firstRefreshRes = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: initialRefreshToken });

    expect(firstRefreshRes.status).toBe(200);
    expect(firstRefreshRes.body.accessToken).toBeDefined();
    expect(firstRefreshRes.body.refreshToken).toBeDefined();
    const newLegitimateRefreshToken = firstRefreshRes.body.refreshToken as string;

    // 3. Attacker (or replay) presents the ALREADY USED initial refresh token
    const replayedRes = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: initialRefreshToken });

    // Must be rejected with 401
    expect(replayedRes.status).toBe(401);
    expect(replayedRes.body.error.code).toBe("AUTH_TOKEN_INVALID");

    // onRefreshReuse hook must have been executed with token info
    expect(onReuseSpy).toHaveBeenCalledTimes(1);
    expect(onReuseSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user-victim",
        familyId: expect.any(String),
        jti: expect.any(String),
      })
    );

    // 4. Because the family was revoked, subsequent refresh with the NEW token must ALSO fail
    const subsequentRefreshRes = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: newLegitimateRefreshToken });

    expect(subsequentRefreshRes.status).toBe(401);
  });

  it("preserves custom application claims across multiple successive rotation hops", async () => {
    const store = createInMemoryRevocationStore();

    const auth = createAuth({
      accessSecret: ACCESS_SECRET,
      refreshSecret: REFRESH_SECRET,
      refreshOptions: {
        rotate: true,
        isRevoked: (jti) => store.isRevoked(jti),
        revokeRefreshToken: async (jti, ctx) => {
          await store.revoke(jti, ctx?.familyId);
        },
        registerRefreshToken: async (jti, ctx) => {
          await store.register(jti, ctx.familyId);
        },
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    // Initial payload with multiple custom claims
    let currentTokenPair = await auth.generateTokenPair({
      id: "u-multi-hop",
      role: "admin",
      organizationId: "org-999",
      features: ["featureA", "featureB"],
    });

    // Perform 3 consecutive rotations
    for (let hop = 1; hop <= 3; hop++) {
      const res = await request(app)
        .post("/auth/refresh")
        .send({ refreshToken: currentTokenPair.refreshToken });

      expect(res.status).toBe(200);

      // Verify the new access token preserves the custom claims
      const accessPayload = await auth.verifyToken(res.body.accessToken);
      expect(accessPayload.id).toBe("u-multi-hop");
      expect(accessPayload.role).toBe("admin");
      expect(accessPayload.organizationId).toBe("org-999");
      expect(accessPayload.features).toEqual(["featureA", "featureB"]);

      currentTokenPair = res.body;
    }
  });

  it("fails closed when revocation store is offline or throws", async () => {
    const auth = createAuth({
      accessSecret: ACCESS_SECRET,
      refreshSecret: REFRESH_SECRET,
      refreshOptions: {
        rotate: true,
        isRevoked: async () => false,
        revokeRefreshToken: async () => {
          throw new Error("Redis cluster connection timeout");
        },
      },
    });

    const app = express();
    app.use(express.json());
    app.post("/auth/refresh", auth.refreshHandler());
    app.use(auth.errorHandler);

    const tokenPair = await auth.generateTokenPair({ id: "user-offline-test" });

    const res = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: tokenPair.refreshToken });

    // Must abort refresh and return 401 fail-closed
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("AUTH_TOKEN_INVALID");
  });
});
