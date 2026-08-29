import { describe, it, expect, vi } from "vitest";
import type { Response } from "express";
import { setCookie } from "../../src/cookies/setCookie.js";
import { clearCookie } from "../../src/cookies/clearCookie.js";

describe("Cookie utilities (setCookie & clearCookie)", () => {
  it("setCookie sets httpOnly cookie with defaults", () => {
    const cookieSpy = vi.fn();
    const res = { cookie: cookieSpy } as unknown as Response;

    setCookie(res, "auth_token", "jwt-value", { maxAge: 900 });

    expect(cookieSpy).toHaveBeenCalledWith(
      "auth_token",
      "jwt-value",
      expect.objectContaining({
        httpOnly: true,
        path: "/",
        sameSite: "lax",
        maxAge: 900000, // converted to ms
      })
    );
  });

  it("clearCookie accepts options object and passes matching domain/path", () => {
    const clearCookieSpy = vi.fn();
    const res = { clearCookie: clearCookieSpy } as unknown as Response;

    clearCookie(res, "auth_token", { path: "/api", domain: ".example.com", secure: true });

    expect(clearCookieSpy).toHaveBeenCalledWith("auth_token", {
      httpOnly: true,
      path: "/api",
      domain: ".example.com",
      sameSite: "lax",
      secure: true,
    });
  });

  it("clearCookie accepts string path argument for backward compatibility", () => {
    const clearCookieSpy = vi.fn();
    const res = { clearCookie: clearCookieSpy } as unknown as Response;

    clearCookie(res, "auth_token", "/custom-path");

    expect(clearCookieSpy).toHaveBeenCalledWith(
      "auth_token",
      expect.objectContaining({
        path: "/custom-path",
        httpOnly: true,
      })
    );
  });
});
