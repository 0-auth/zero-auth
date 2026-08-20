import { describe, it, expect } from "vitest";
import { signToken } from "../../src/core/sign.js";

const SECRET = "test-secret-that-is-at-least-32-characters-long";

describe("signToken", () => {
  it("returns a JWT string (three dot-separated parts)", async () => {
    const token = await signToken({ id: "user-1" }, SECRET, "15m");
    const parts = token.split(".");
    expect(parts).toHaveLength(3);
  });

  it("embeds the payload claims", async () => {
    const payload = { id: "user-42", email: "test@example.com", role: "admin" };
    const token = await signToken(payload, SECRET, "15m");

    // Decode the payload section (base64url)
    const payloadJson = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf-8")
    ) as Record<string, unknown>;

    expect(payloadJson["id"]).toBe("user-42");
    expect(payloadJson["email"]).toBe("test@example.com");
    expect(payloadJson["role"]).toBe("admin");
  });

  it("sets the iat claim", async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await signToken({ id: "user-1" }, SECRET, "15m");
    const after = Math.floor(Date.now() / 1000);

    const payloadJson = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf-8")
    ) as Record<string, unknown>;

    expect(typeof payloadJson["iat"]).toBe("number");
    expect(payloadJson["iat"] as number).toBeGreaterThanOrEqual(before);
    expect(payloadJson["iat"] as number).toBeLessThanOrEqual(after);
  });

  it("sets the exp claim to approximately 15 minutes from now", async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await signToken({ id: "user-1" }, SECRET, "15m");

    const payloadJson = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf-8")
    ) as Record<string, unknown>;

    const exp = payloadJson["exp"] as number;
    // Should be around before + 900 seconds (15 minutes)
    expect(exp).toBeGreaterThanOrEqual(before + 890);
    expect(exp).toBeLessThanOrEqual(before + 920);
  });

  it("sets the jti claim", async () => {
    const token = await signToken({ id: "user-1" }, SECRET, "15m");
    const payloadJson = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf-8")
    ) as Record<string, unknown>;

    expect(typeof payloadJson["jti"]).toBe("string");
    expect((payloadJson["jti"] as string).length).toBeGreaterThan(0);
  });

  it("generates unique jti values for each call", async () => {
    const [t1, t2] = await Promise.all([
      signToken({ id: "u" }, SECRET, "15m"),
      signToken({ id: "u" }, SECRET, "15m"),
    ]);

    const jti1 = JSON.parse(Buffer.from(t1.split(".")[1]!, "base64url").toString("utf-8")) as Record<string, unknown>;
    const jti2 = JSON.parse(Buffer.from(t2.split(".")[1]!, "base64url").toString("utf-8")) as Record<string, unknown>;

    expect(jti1["jti"]).not.toBe(jti2["jti"]);
  });

  it("supports day expiry format", async () => {
    const token = await signToken({ id: "user-1" }, SECRET, "7d");
    const payloadJson = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf-8")
    ) as Record<string, unknown>;

    const now = Math.floor(Date.now() / 1000);
    const exp = payloadJson["exp"] as number;
    // 7d = 604800 seconds
    expect(exp).toBeGreaterThan(now + 604790);
  });
});
