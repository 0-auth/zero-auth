import { describe, it, expect } from "vitest";
import { signToken } from "../../src/core/sign.js";
import { verifyToken } from "../../src/core/verify.js";
import { AuthError } from "../../src/errors/authErrors.js";

const SECRET = "test-secret-that-is-at-least-32-characters-long";
const WRONG_SECRET = "wrong-secret-that-is-also-32-chars-long-x";

describe("verifyToken", () => {
  it("returns the decoded payload for a valid token", async () => {
    const payload = { id: "user-1", email: "a@b.com", role: "user" };
    const token = await signToken(payload, SECRET, "15m");
    const decoded = await verifyToken(token, SECRET);

    expect(decoded.id).toBe("user-1");
    expect(decoded.email).toBe("a@b.com");
    expect(decoded.role).toBe("user");
  });

  it("throws AUTH_TOKEN_INVALID for a tampered token", async () => {
    const token = await signToken({ id: "user-1" }, SECRET, "15m");
    // Tamper with the payload section.
    const parts = token.split(".");
    const tamperedPayload = Buffer.from(JSON.stringify({ id: "hacker", role: "admin" })).toString(
      "base64url"
    );
    const tampered = [parts[0], tamperedPayload, parts[2]].join(".");

    await expect(verifyToken(tampered, SECRET)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("throws AUTH_TOKEN_INVALID for a token signed with the wrong secret", async () => {
    const token = await signToken({ id: "user-1" }, WRONG_SECRET, "15m");

    await expect(verifyToken(token, SECRET)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("throws AUTH_TOKEN_EXPIRED for an expired token", async () => {
    const token = await signToken({ id: "user-1" }, SECRET, "1s");
    // Wait for expiry.
    await new Promise((r) => setTimeout(r, 1100));

    await expect(verifyToken(token, SECRET)).rejects.toMatchObject({
      code: "AUTH_TOKEN_EXPIRED",
    });
  });

  it("throws AUTH_TOKEN_INVALID for a malformed token string", async () => {
    await expect(verifyToken("not.a.jwt", SECRET)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("throws AUTH_TOKEN_INVALID for an empty string", async () => {
    await expect(verifyToken("", SECRET)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("throws AUTH_TOKEN_INVALID when the `id` claim is missing", async () => {
    // Sign a token without `id` using raw jose to bypass our signToken.
    const { SignJWT } = await import("jose");
    const secretKey = new TextEncoder().encode(SECRET);
    const token = await new SignJWT({ email: "no-id@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("15m")
      .sign(secretKey);

    await expect(verifyToken(token, SECRET)).rejects.toMatchObject({
      code: "AUTH_TOKEN_INVALID",
    });
  });

  it("verifyToken errors are instances of AuthError", async () => {
    await expect(verifyToken("bad.token.here", SECRET)).rejects.toBeInstanceOf(AuthError);
  });
});
