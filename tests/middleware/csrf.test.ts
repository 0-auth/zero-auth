import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import { createCsrfMiddleware, createCsrfToken } from "../../src/middleware/csrf.js";
import { AuthError } from "../../src/errors/authErrors.js";
import { resolveConfig } from "../../src/utils/helpers.js";
import { createAuth } from "../../src/index.js";

const config = resolveConfig({
  accessSecret: "csrf-access-secret-that-is-at-least-32-chars",
  refreshSecret: "csrf-refresh-secret-that-is-at-least-32-chars",
});

function makeReq(
  method = "POST",
  headers: Record<string, string> = {},
  cookies?: Record<string, string>
): Request {
  return {
    method,
    headers,
    cookies,
    get(name: string) {
      return headers[name.toLowerCase()];
    },
  } as unknown as Request;
}

function makeRes(): Response & { cookie: ReturnType<typeof vi.fn> } {
  return { cookie: vi.fn() } as unknown as Response & { cookie: ReturnType<typeof vi.fn> };
}

describe("csrf middleware", () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    next = vi.fn();
  });

  it("sets a readable signed CSRF cookie and returns the same token", () => {
    const res = makeRes();
    const token = createCsrfToken(res, config);

    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(res.cookie).toHaveBeenCalledWith(
      "csrf_token",
      token,
      expect.objectContaining({ httpOnly: false, sameSite: "lax", path: "/" })
    );
  });

  it("exposes CSRF setup through createAuth", () => {
    const auth = createAuth({
      accessSecret: config.accessSecret,
      refreshSecret: config.refreshSecret,
    });
    const res = makeRes();
    const token = auth.csrfToken(res);

    auth.csrf()(
      makeReq("POST", {
        cookie: `access_token=present; csrf_token=${encodeURIComponent(token)}`,
        "x-csrf-token": token,
      }),
      makeRes(),
      next as NextFunction
    );

    expect(next).toHaveBeenCalledWith();
  });

  it("allows safe methods without a CSRF token", () => {
    const csrf = createCsrfMiddleware(config);

    csrf(makeReq("GET", { cookie: "access_token=present" }), makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledWith();
  });

  it("allows state-changing requests without auth cookies", () => {
    const csrf = createCsrfMiddleware(config);

    csrf(makeReq("POST"), makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledWith();
  });

  it("rejects an authenticated request without a CSRF token", () => {
    const csrf = createCsrfMiddleware(config);

    csrf(makeReq("POST", { cookie: "access_token=present" }), makeRes(), next as NextFunction);

    const error = next.mock.calls[0]?.[0] as AuthError;
    expect(error).toBeInstanceOf(AuthError);
    expect(error.code).toBe("AUTH_CSRF_INVALID");
    expect(error.statusCode).toBe(403);
  });

  it("allows a matching signed cookie and header", () => {
    const res = makeRes();
    const token = createCsrfToken(res, config);
    const csrf = createCsrfMiddleware(config);

    csrf(
      makeReq("POST", {
        cookie: `access_token=present; csrf_token=${encodeURIComponent(token)}`,
        "x-csrf-token": token,
      }),
      makeRes(),
      next as NextFunction
    );

    expect(next).toHaveBeenCalledWith();
  });

  it("rejects mismatched, tampered, and malformed tokens", () => {
    const res = makeRes();
    const token = createCsrfToken(res, config);
    const csrf = createCsrfMiddleware(config);

    for (const headerToken of ["different", `${token}tampered`, "malformed.token.extra"]) {
      next.mockClear();
      csrf(
        makeReq("POST", {
          cookie: `refresh_token=present; csrf_token=${encodeURIComponent(token)}`,
          "x-csrf-token": headerToken,
        }),
        makeRes(),
        next as NextFunction
      );

      expect((next.mock.calls[0]?.[0] as AuthError).code).toBe("AUTH_CSRF_INVALID");
    }
  });

  it("supports custom methods and cookie-parser values", () => {
    const customConfig = resolveConfig({
      accessSecret: "csrf-access-secret-that-is-at-least-32-chars",
      refreshSecret: "csrf-refresh-secret-that-is-at-least-32-chars",
      csrf: { methods: ["PATCH"] },
    });
    const res = makeRes();
    const token = createCsrfToken(res, customConfig);
    const csrf = createCsrfMiddleware(customConfig);

    csrf(
      makeReq("PATCH", { "x-csrf-token": token }, { access_token: "present", csrf_token: token }),
      makeRes(),
      next as NextFunction
    );

    expect(next).toHaveBeenCalledWith();
  });
});
