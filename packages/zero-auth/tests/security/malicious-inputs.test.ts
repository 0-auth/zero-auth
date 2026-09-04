import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import { createAuth, verifyToken, decodeToken, AuthError, isAuthError } from "../../src/index.js";

const SECRET = "a-very-secure-and-long-access-secret-32-chars!!";
const REFRESH_SECRET = "a-very-secure-and-long-refresh-secret-32-chars!";

describe("Security Audit: Malicious Inputs & Attack Vectors", () => {
  const auth = createAuth({
    accessSecret: SECRET,
    refreshSecret: REFRESH_SECRET,
  });

  describe("1. Algorithm Confusion & Forgery Attacks", () => {
    it("rejects unsigned tokens with alg: 'none'", async () => {
      // Unsigned token header + payload with empty signature: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6InVzZXItMSIsInJvbGUiOiJhZG1pbiJ9.
      const noneToken =
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6InVzZXItMSIsInJvbGUiOiJhZG1pbiJ9.";

      await expect(auth.verifyToken(noneToken)).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken(noneToken)).rejects.toMatchObject({
        code: "AUTH_TOKEN_INVALID",
        statusCode: 401,
      });
    });

    it("rejects tokens signed with an unsupported algorithm (e.g. HS384 / HS512 / RS256)", async () => {
      const secretKey = new TextEncoder().encode(SECRET);
      // Sign with HS512 instead of allowed HS256
      const hs512Token = await new SignJWT({ id: "user-attacker" })
        .setProtectedHeader({ alg: "HS512" })
        .sign(secretKey);

      await expect(auth.verifyToken(hs512Token)).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken(hs512Token)).rejects.toMatchObject({
        code: "AUTH_TOKEN_INVALID",
      });
    });

    it("rejects tokens signed with a different secret (signature mismatch)", async () => {
      const wrongSecret = "completely-different-secret-key-32-characters!";
      const forgedToken = await auth.generateAccessToken({ id: "attacker-user" });

      // Verifying with wrong secret must reject
      await expect(verifyToken(forgedToken, wrongSecret)).rejects.toThrowError(AuthError);
    });

    it("rejects tokens where the payload was modified after signing (tampering attack)", async () => {
      const validToken = await auth.generateAccessToken({ id: "user-1", role: "user" });
      const parts = validToken.split(".");
      expect(parts).toHaveLength(3);

      // Attacker decodes payload, changes role to admin, and re-encodes
      const tamperedPayload = Buffer.from(
        JSON.stringify({ id: "user-1", role: "admin", exp: Math.floor(Date.now() / 1000) + 3600 })
      ).toString("base64url");

      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      await expect(auth.verifyToken(tamperedToken)).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken(tamperedToken)).rejects.toMatchObject({
        code: "AUTH_TOKEN_INVALID",
      });
    });

    it("rejects tokens where the header was modified after signing", async () => {
      const validToken = await auth.generateAccessToken({ id: "user-1" });
      const parts = validToken.split(".");

      // Modify header
      const tamperedHeader = Buffer.from(
        JSON.stringify({ alg: "HS256", typ: "JWT", kid: "injected" })
      ).toString("base64url");

      const tamperedToken = `${tamperedHeader}.${parts[1]}.${parts[2]}`;

      await expect(auth.verifyToken(tamperedToken)).rejects.toThrowError(AuthError);
    });
  });

  describe("2. Malformed, Truncated & Boundary Tokens", () => {
    it("rejects empty strings and whitespace strings", async () => {
      await expect(auth.verifyToken("")).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken("   ")).rejects.toThrowError(AuthError);
    });

    it("rejects truncated tokens (missing signature or payload)", async () => {
      await expect(auth.verifyToken("eyJhbGciOiJIUzI1NiJ9")).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken("eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEifQ")).rejects.toThrowError(
        AuthError
      );
    });

    it("rejects tokens with extra dot-separated segments", async () => {
      const validToken = await auth.generateAccessToken({ id: "user-1" });
      const extraPartsToken = `${validToken}.extra.segment`;
      await expect(auth.verifyToken(extraPartsToken)).rejects.toThrowError(AuthError);
    });

    it("rejects tokens with invalid non-base64 characters and null bytes", async () => {
      await expect(auth.verifyToken("invalid\0token.with.nullbytes")).rejects.toThrowError(
        AuthError
      );
      await expect(auth.verifyToken("!@#$%^&*().!@#$%^&*().!@#$%^&*()")).rejects.toThrowError(
        AuthError
      );
    });

    it("rejects validly signed tokens missing the required `id` claim", async () => {
      const secretKey = new TextEncoder().encode(SECRET);
      // Valid signature, but payload has no `id`
      const noIdToken = await new SignJWT({ email: "test@example.com", role: "admin" })
        .setProtectedHeader({ alg: "HS256" })
        .sign(secretKey);

      await expect(auth.verifyToken(noIdToken)).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken(noIdToken)).rejects.toMatchObject({
        code: "AUTH_TOKEN_INVALID",
        message: expect.stringContaining("id"),
      });
    });

    it("handles safe decoding of malformed tokens without crashing", () => {
      expect(() => decodeToken("not.a.valid.jwt")).toThrowError(AuthError);
      expect(() => decodeToken("invalid")).toThrowError(AuthError);
      expect(() => decodeToken("")).toThrowError(AuthError);
    });
  });

  describe("3. Secret Isolation & Access vs Refresh Separation", () => {
    it("rejects using a refresh token as an access token", async () => {
      const refreshToken = await auth.generateRefreshToken({ id: "user-1" });

      // Attempting to verify a refresh token with verifyToken (which uses accessSecret) must fail
      await expect(auth.verifyToken(refreshToken)).rejects.toThrowError(AuthError);
      await expect(auth.verifyToken(refreshToken)).rejects.toMatchObject({
        code: "AUTH_TOKEN_INVALID",
      });
    });

    it("rejects using an access token as a refresh token", async () => {
      const accessToken = await auth.generateAccessToken({ id: "user-1" });

      // Attempting to verify an access token with verifyRefreshToken (which uses refreshSecret) must fail
      await expect(auth.verifyRefreshToken(accessToken)).rejects.toThrowError(AuthError);
      await expect(auth.verifyRefreshToken(accessToken)).rejects.toMatchObject({
        code: "AUTH_TOKEN_INVALID",
      });
    });
  });

  describe("4. Error Object Safety & Information Disclosure", () => {
    it("does not leak secret keys or sensitive internal data in AuthError.toJSON()", () => {
      const err = new AuthError("AUTH_TOKEN_INVALID", "Invalid token signature");
      const json = err.toJSON();

      expect(json).toEqual({
        error: {
          code: "AUTH_TOKEN_INVALID",
          message: "Invalid token signature",
          statusCode: 401,
        },
      });
      expect(JSON.stringify(json)).not.toContain(SECRET);
      expect(JSON.stringify(json)).not.toContain("stack");
    });

    it("isAuthError correctly identifies AuthError instances and ignores generic Errors", () => {
      const authErr = new AuthError("AUTH_FORBIDDEN");
      const standardErr = new Error("Generic error");

      expect(isAuthError(authErr)).toBe(true);
      expect(isAuthError(standardErr)).toBe(false);
      expect(isAuthError(null)).toBe(false);
      expect(isAuthError(undefined)).toBe(false);
      expect(isAuthError({ code: "AUTH_FORBIDDEN" })).toBe(false);
    });
  });
});
