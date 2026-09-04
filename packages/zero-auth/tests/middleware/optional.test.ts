import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { createOptionalMiddleware } from "../../src/middleware/optional.js";
import { createJwtEngine, type JwtEngine } from "../../src/core/jwt.js";
import { resolveConfig } from "../../src/utils/helpers.js";
import { signToken } from "../../src/core/sign.js";

const config = resolveConfig({
  accessSecret: "optional-access-secret-32-chars-long!",
  refreshSecret: "optional-refresh-secret-32-chars-long",
});
const engine = createJwtEngine(config);
const optional = createOptionalMiddleware(engine, config);

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    method: "GET",
    path: "/public-article",
    ...overrides,
  } as unknown as Request;
}

function makeRes(): Response {
  return {} as Response;
}

describe("optional middleware", () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    next = vi.fn();
  });

  it("calls next() without setting req.user when no token is present", () => {
    const req = makeReq();
    optional(req, makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledWith();
    expect((req as Request & { user?: unknown }).user).toBeUndefined();
  });

  it("attaches req.user and calls next() when a valid token is present", async () => {
    const token = await signToken({ id: "user-opt-1" }, config.accessSecret, "15m");
    const req = makeReq({
      headers: { authorization: `Bearer ${token}` },
    });

    optional(req, makeRes(), next as NextFunction);
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    expect(next).toHaveBeenCalledWith();
    expect((req as Request & { user?: { id: string } }).user?.id).toBe("user-opt-1");
  });

  it("calls next() without failing when an invalid/expired token is present (treats as guest)", async () => {
    const req = makeReq({
      headers: { authorization: "Bearer completely.invalid.jwt" },
    });

    optional(req, makeRes(), next as NextFunction);
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    // Never calls next with error
    expect(next).toHaveBeenCalledWith();
    expect((req as Request & { user?: unknown }).user).toBeUndefined();
  });

  it("handles unexpected verification errors gracefully by treating user as guest", async () => {
    const mockEngine = {
      ...engine,
      verifyAccessToken: vi.fn().mockRejectedValue(new Error("Unexpected error")),
    };
    const mockOptional = createOptionalMiddleware(mockEngine as unknown as JwtEngine, config);

    const req = makeReq({
      headers: { authorization: "Bearer some-token" },
    });

    mockOptional(req, makeRes(), next as NextFunction);
    await vi.waitFor(() => expect(next).toHaveBeenCalledOnce());

    expect(next).toHaveBeenCalledWith();
    expect((req as Request & { user?: unknown }).user).toBeUndefined();
  });
});
