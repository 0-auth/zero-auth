import { describe, it, expect } from "vitest";
import type { Request } from "express";
import {
  createAuth,
  parseCookieHeader,
  extractToken,
  extractRefreshToken,
} from "../../src/index.js";
import type { CookieOptions } from "../../src/types/cookies.js";

const ACCESS_SECRET = "access-secret-for-cookie-audit-32-chars!";
const REFRESH_SECRET = "refresh-secret-for-cookie-audit-32-chars";

describe("Security Audit: Cookie & Header Extraction Safety", () => {
  describe("Cookie parser edge cases", () => {
    it("handles null, undefined, empty, and malformed cookie headers gracefully", () => {
      expect(parseCookieHeader("")).toEqual({});
      expect(parseCookieHeader("   ")).toEqual({});
      expect(parseCookieHeader("invalid; ; = ; ;foo=")).toEqual({ foo: "" });
      expect(parseCookieHeader("session=abc=123; user=john%20doe")).toEqual({
        session: "abc=123",
        user: "john doe",
      });
    });

    it("handles URI-encoded values and unencodable malformed UTF-8 gracefully without crashing", () => {
      // %E0%A4%A is invalid incomplete UTF-8
      const parsed = parseCookieHeader("token=%E0%A4%A; valid=hello");
      expect(parsed.valid).toBe("hello");
      // Fallbacks to raw value when decodeURIComponent fails
      expect(parsed.token).toBe("%E0%A4%A");
    });
  });

  describe("Token extraction edge cases", () => {
    it("ignores non-Bearer authorization headers (e.g. Basic, Digest)", () => {
      const req = {
        headers: {
          authorization: "Basic dXNlcjpwYXNz",
        },
      };
      expect(extractToken(req as unknown as Request)).toBeNull();
    });

    it("ignores empty Bearer tokens or whitespace tokens", () => {
      expect(
        extractToken({ headers: { authorization: "Bearer " } } as unknown as Request)
      ).toBeNull();
      expect(
        extractToken({ headers: { authorization: "Bearer    " } } as unknown as Request)
      ).toBeNull();
      expect(
        extractToken({ headers: { authorization: "Bearer" } } as unknown as Request)
      ).toBeNull();
    });

    it("prefers Bearer header over cookie for access tokens", () => {
      const req = {
        headers: {
          authorization: "Bearer header-token",
          cookie: "access_token=cookie-token",
        },
      };
      expect(extractToken(req as unknown as Request, "access_token")).toBe("header-token");
    });

    it("extracts access token from cookie when header is missing", () => {
      const req = {
        headers: {
          cookie: "access_token=cookie-token",
        },
      };
      expect(extractToken(req as unknown as Request, "access_token")).toBe("cookie-token");
    });

    it("prefers cookie over body and Bearer for refresh tokens (SPA-safe)", () => {
      const req = {
        headers: {
          cookie: "refresh_token=cookie-refresh",
          authorization: "Bearer header-access-token",
        },
        body: {
          refreshToken: "body-refresh",
        },
      };
      expect(extractRefreshToken(req as unknown as Request, "refresh_token")).toBe(
        "cookie-refresh"
      );
    });
  });

  describe("Cookie security flags enforcement", () => {
    it("always enforces httpOnly: true and prevents overriding to false", () => {
      const auth = createAuth({
        accessSecret: ACCESS_SECRET,
        refreshSecret: REFRESH_SECRET,
        cookies: {
          options: {
            // Attempt to disable httpOnly
            httpOnly: false as unknown as boolean,
          } as CookieOptions,
        },
      });

      expect(auth.config.cookies.options.httpOnly).toBe(true);
    });
  });
});
