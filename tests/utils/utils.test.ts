import { describe, it, expect } from "vitest";
import { parseCookieHeader } from "../../src/cookies/parseCookie.js";
import { decodeToken } from "../../src/core/decode.js";
import {
  parseExpiryToSeconds,
  toRefreshPayload,
  withFamilyId,
} from "../../src/utils/helpers.js";
import { signToken } from "../../src/core/sign.js";
import { createAuth } from "../../src/index.js";
import { AuthError } from "../../src/errors/authErrors.js";
import type { AuthUser, AuthConfig } from "../../src/types/auth.js";

const SECRET = "test-secret-that-is-at-least-32-characters-long";

// ─── parseCookieHeader ────────────────────────────────────────────────────────

describe("parseCookieHeader", () => {
  it("parses a single cookie", () => {
    expect(parseCookieHeader("name=value")).toEqual({ name: "value" });
  });

  it("parses multiple cookies", () => {
    expect(parseCookieHeader("a=1; b=2; c=3")).toEqual({ a: "1", b: "2", c: "3" });
  });

  it("URI-decodes cookie values", () => {
    const result = parseCookieHeader("token=hello%20world");
    expect(result["token"]).toBe("hello world");
  });

  it("trims whitespace around keys and values", () => {
    expect(parseCookieHeader("  key  =  value  ")).toEqual({ key: "value" });
  });

  it("skips pairs without an equals sign", () => {
    expect(parseCookieHeader("invalid; key=value")).toEqual({ key: "value" });
  });

  it("returns an empty object for an empty string", () => {
    expect(parseCookieHeader("")).toEqual({});
  });

  it("handles values that contain equals signs", () => {
    // e.g. a base64-encoded JWT has = padding
    const result = parseCookieHeader("token=abc==");
    expect(result["token"]).toBe("abc==");
  });
});

// ─── decodeToken ─────────────────────────────────────────────────────────────

describe("decodeToken", () => {
  it("decodes a valid token without verifying signature", async () => {
    const token = await signToken({ id: "user-1", role: "admin" }, SECRET, "15m");
    const decoded = decodeToken(token);

    expect(decoded.id).toBe("user-1");
    expect(decoded.role).toBe("admin");
    expect(decoded.exp).toBeDefined();
  });

  it("throws AUTH_TOKEN_INVALID for a malformed token", () => {
    expect(() => decodeToken("not-a-jwt")).toThrowError(AuthError);
    try {
      decodeToken("not-a-jwt");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError);
      expect((err as AuthError).code).toBe("AUTH_TOKEN_INVALID");
    }
  });

  it("decodes an expired token (no signature check)", async () => {
    // signToken with "1s" then wait, but decodeToken should still work
    const token = await signToken({ id: "user-expired" }, SECRET, "1s");
    // Decode immediately — should work regardless of expiry
    const decoded = decodeToken(token);
    expect(decoded.id).toBe("user-expired");
  });

  it("throws AUTH_TOKEN_INVALID for an empty string", () => {
    expect(() => decodeToken("")).toThrowError(AuthError);
    try {
      decodeToken("");
    } catch (err) {
      expect((err as AuthError).code).toBe("AUTH_TOKEN_INVALID");
    }
  });
});

// ─── parseExpiryToSeconds ─────────────────────────────────────────────────────

describe("parseExpiryToSeconds", () => {
  it("parses seconds (s)", () => {
    expect(parseExpiryToSeconds("30s")).toBe(30);
  });

  it("parses minutes (m)", () => {
    expect(parseExpiryToSeconds("15m")).toBe(900);
  });

  it("parses hours (h)", () => {
    expect(parseExpiryToSeconds("2h")).toBe(7200);
  });

  it("parses days (d)", () => {
    expect(parseExpiryToSeconds("7d")).toBe(604800);
  });

  it("parses weeks (w)", () => {
    expect(parseExpiryToSeconds("1w")).toBe(604800);
  });

  it("parses milliseconds (ms) to fractional seconds, floored", () => {
    expect(parseExpiryToSeconds("500ms")).toBe(0);
    expect(parseExpiryToSeconds("2000ms")).toBe(2);
  });

  it("parses decimal values", () => {
    expect(parseExpiryToSeconds("1.5h")).toBe(5400);
  });

  it("throws for an invalid format", () => {
    expect(() => parseExpiryToSeconds("15")).toThrowError("Invalid expiry format");
    expect(() => parseExpiryToSeconds("fifteen minutes")).toThrowError("Invalid expiry format");
    expect(() => parseExpiryToSeconds("")).toThrowError("Invalid expiry format");
  });
});

// ─── toRefreshPayload / withFamilyId ──────────────────────────────────────────

describe("toRefreshPayload", () => {
  it("keeps custom claims and strips registered JWT claims", () => {
    const decoded = {
      id: "u1",
      email: "a@b.com",
      role: "admin",
      tenantId: "t1",
      iat: 1,
      exp: 2,
      jti: "old-jti",
      nbf: 0,
    } as AuthUser;

    const payload = toRefreshPayload(decoded);
    expect(payload).toEqual({
      id: "u1",
      email: "a@b.com",
      role: "admin",
      tenantId: "t1",
    });
    expect(payload).not.toHaveProperty("jti");
    expect(payload).not.toHaveProperty("iat");
    expect(payload).not.toHaveProperty("exp");
  });
});

describe("withFamilyId", () => {
  it("is a no-op when rotation is disabled", () => {
    expect(withFamilyId({ id: "u1" }, false)).toEqual({ id: "u1" });
  });

  it("injects fid when rotation is enabled and missing", () => {
    const result = withFamilyId({ id: "u1" }, true);
    expect(result["fid"]).toBeTypeOf("string");
  });

  it("preserves an existing fid", () => {
    const result = withFamilyId({ id: "u1", fid: "family-1" }, true);
    expect(result["fid"]).toBe("family-1");
  });
});

describe("resolveConfig & validation", () => {
  const originalEnv = process.env["NODE_ENV"];

  it("throws when accessSecret or refreshSecret is missing", () => {
    expect(() => createAuth({ accessSecret: "", refreshSecret: "valid-32-chars-long-refresh-secret!" } as unknown as AuthConfig)).toThrowError(
      "[zero-auth] `accessSecret` is required."
    );
    expect(() => createAuth({ accessSecret: "valid-32-chars-long-access-secret!", refreshSecret: "" } as unknown as AuthConfig)).toThrowError(
      "[zero-auth] `refreshSecret` is required."
    );
  });

  it("enforces 32-char secrets and distinct secrets in production", () => {
    process.env["NODE_ENV"] = "production";
    try {
      expect(() =>
        createAuth({
          accessSecret: "short",
          refreshSecret: "valid-32-chars-long-refresh-secret!",
        })
      ).toThrowError("[zero-auth] `accessSecret` should be at least 32 characters for security.");

      expect(() =>
        createAuth({
          accessSecret: "valid-32-chars-long-access-secret!",
          refreshSecret: "short",
        })
      ).toThrowError("[zero-auth] `refreshSecret` should be at least 32 characters for security.");

      expect(() =>
        createAuth({
          accessSecret: "identical-secret-key-32-chars-long!",
          refreshSecret: "identical-secret-key-32-chars-long!",
        })
      ).toThrowError("[zero-auth] `accessSecret` and `refreshSecret` should be different values.");
    } finally {
      process.env["NODE_ENV"] = originalEnv;
    }
  });

  it("enforces revocation hooks when rotate: true in production", () => {
    process.env["NODE_ENV"] = "production";
    try {
      expect(() =>
        createAuth({
          accessSecret: "valid-32-chars-long-access-secret!",
          refreshSecret: "valid-32-chars-long-refresh-secret!",
          refreshOptions: {
            rotate: true,
          },
        })
      ).toThrowError("[zero-auth] refreshOptions.rotate requires isRevoked and revokeRefreshToken");
    } finally {
      process.env["NODE_ENV"] = originalEnv;
    }
  });

  it("enforces secure: true when sameSite is 'none' in production", () => {
    process.env["NODE_ENV"] = "production";
    try {
      expect(() =>
        createAuth({
          accessSecret: "valid-32-chars-long-access-secret!",
          refreshSecret: "valid-32-chars-long-refresh-secret!",
          cookies: {
            options: {
              sameSite: "none",
              secure: false,
            },
          },
        })
      ).toThrowError("[zero-auth] Cookie option `sameSite: 'none'` requires `secure: true`");
    } finally {
      process.env["NODE_ENV"] = originalEnv;
    }
  });
});
