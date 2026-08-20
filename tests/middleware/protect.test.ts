import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { createProtectMiddleware } from "../../src/middleware/protect.js";
import { createJwtEngine } from "../../src/core/jwt.js";
import { resolveConfig } from "../../src/utils/helpers.js";
import { AuthError } from "../../src/errors/authErrors.js";
import { signToken } from "../../src/core/sign.js";

const config = resolveConfig({
  accessSecret: "access-secret-that-is-at-least-32-chars-ok",
  refreshSecret: "refresh-secret-that-is-at-least-32-chars",
});
const engine = createJwtEngine(config);
const protect = createProtectMiddleware(engine, config);

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    method: "GET",
    path: "/test",
    ...overrides,
  } as unknown as Request;
}

function makeRes(): Response {
  return {} as Response;
}

describe("protect middleware", () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    next = vi.fn();
  });

  it("calls next(AuthError[AUTH_TOKEN_MISSING]) when no token is present", () => {
    const req = makeReq();
    protect(req, makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledOnce();
    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg).toBeInstanceOf(AuthError);
    expect(arg.code).toBe("AUTH_TOKEN_MISSING");
  });

  it("attaches req.user and calls next() for a valid Bearer token", async () => {
    const token = await signToken({ id: "user-99" }, config.accessSecret, "15m");
    const req = makeReq({
      headers: { authorization: `Bearer ${token}` },
    });

    protect(req, makeRes(), next as NextFunction);

    // Wait for async verification.
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    expect(next).toHaveBeenCalledWith(); // no error arg
    expect((req as Request & { user?: { id: string } }).user?.id).toBe("user-99");
  });

  it("calls next(AuthError[AUTH_TOKEN_INVALID]) for a tampered token", async () => {
    const req = makeReq({
      headers: { authorization: "Bearer invalid.token.here" },
    });

    protect(req, makeRes(), next as NextFunction);

    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg).toBeInstanceOf(AuthError);
    expect(arg.code).toBe("AUTH_TOKEN_INVALID");
  });

  it("calls next(AuthError[AUTH_TOKEN_EXPIRED]) for an expired token", async () => {
    const token = await signToken({ id: "user-1" }, config.accessSecret, "1s");
    await new Promise((r) => setTimeout(r, 1100));

    const req = makeReq({
      headers: { authorization: `Bearer ${token}` },
    });

    protect(req, makeRes(), next as NextFunction);
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg.code).toBe("AUTH_TOKEN_EXPIRED");
  });

  it("reads the token from a cookie when no Authorization header is present", async () => {
    const token = await signToken({ id: "cookie-user" }, config.accessSecret, "15m");
    const req = makeReq({
      headers: { cookie: `access_token=${token}` },
    });

    protect(req, makeRes(), next as NextFunction);
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    expect(next).toHaveBeenCalledWith();
    expect((req as Request & { user?: { id: string } }).user?.id).toBe("cookie-user");
  });

  it("prefers Authorization header over cookie", async () => {
    const headerToken = await signToken({ id: "header-user" }, config.accessSecret, "15m");
    const cookieToken = await signToken({ id: "cookie-user" }, config.accessSecret, "15m");

    const req = makeReq({
      headers: {
        authorization: `Bearer ${headerToken}`,
        cookie: `access_token=${cookieToken}`,
      },
    });

    protect(req, makeRes(), next as NextFunction);
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    expect((req as Request & { user?: { id: string } }).user?.id).toBe("header-user");
  });
});
