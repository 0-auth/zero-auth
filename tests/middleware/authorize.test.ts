import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import {
  createAuthorizeMiddleware,
  createAuthorizePermissionsMiddleware,
} from "../../src/middleware/authorize.js";
import { AuthError } from "../../src/errors/authErrors.js";
import type { AuthUser } from "../../src/types/auth.js";

function makeReq(user?: AuthUser): Request {
  return { user } as unknown as Request;
}

function makeRes(): Response {
  return {} as Response;
}

describe("authorize middleware", () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    next = vi.fn();
  });

  it("throws if no roles are provided", () => {
    expect(() => createAuthorizeMiddleware([])).toThrowError(
      "[zero-auth] `authorize()` requires at least one role."
    );
  });

  it("calls next() when the user's role matches", () => {
    const authorize = createAuthorizeMiddleware(["admin"]);
    const req = makeReq({ id: "u1", role: "admin" });

    authorize(req, makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledWith(); // no error
  });

  it("calls next() when the user's role is one of multiple allowed roles", () => {
    const authorize = createAuthorizeMiddleware(["admin", "moderator"]);
    const req = makeReq({ id: "u1", role: "moderator" });

    authorize(req, makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledWith();
  });

  it("calls next(AuthError[AUTH_FORBIDDEN]) when role does not match", () => {
    const authorize = createAuthorizeMiddleware(["admin"]);
    const req = makeReq({ id: "u1", role: "user" });

    authorize(req, makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg).toBeInstanceOf(AuthError);
    expect(arg.code).toBe("AUTH_FORBIDDEN");
    expect(arg.statusCode).toBe(403);
  });

  it("calls next(AuthError[AUTH_FORBIDDEN]) when user has no role", () => {
    const authorize = createAuthorizeMiddleware(["admin"]);
    const req = makeReq({ id: "u1" }); // no role

    authorize(req, makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg.code).toBe("AUTH_FORBIDDEN");
  });

  it("calls next(AuthError[AUTH_UNAUTHORIZED]) when req.user is not set", () => {
    const authorize = createAuthorizeMiddleware(["admin"]);
    const req = makeReq(undefined);

    authorize(req, makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg).toBeInstanceOf(AuthError);
    expect(arg.code).toBe("AUTH_UNAUTHORIZED");
  });

  it("is case-sensitive for role matching", () => {
    const authorize = createAuthorizeMiddleware(["Admin"]);
    const req = makeReq({ id: "u1", role: "admin" }); // lowercase

    authorize(req, makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg.code).toBe("AUTH_FORBIDDEN");
  });
});

describe("authorizePermissions middleware", () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    next = vi.fn();
  });

  it("throws if no permissions are provided", () => {
    expect(() => createAuthorizePermissionsMiddleware([])).toThrowError(
      "[zero-auth] `authorizePermissions()` requires at least one permission."
    );
  });

  it("calls next() when the user has every required permission", () => {
    const authorize = createAuthorizePermissionsMiddleware(["users:read", "users:update"]);
    const req = makeReq({
      id: "u1",
      permissions: ["users:read", "users:update", "users:delete"],
    });

    authorize(req, makeRes(), next as NextFunction);

    expect(next).toHaveBeenCalledWith();
  });

  it("calls next(AuthError[AUTH_FORBIDDEN]) when a permission is missing", () => {
    const authorize = createAuthorizePermissionsMiddleware(["users:read"]);
    const req = makeReq({ id: "u1", permissions: ["users:update"] });

    authorize(req, makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg).toBeInstanceOf(AuthError);
    expect(arg.code).toBe("AUTH_FORBIDDEN");
    expect(arg.statusCode).toBe(403);
  });

  it("calls next(AuthError[AUTH_FORBIDDEN]) when permissions are absent", () => {
    const authorize = createAuthorizePermissionsMiddleware(["users:read"]);
    const req = makeReq({ id: "u1" });

    authorize(req, makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg.code).toBe("AUTH_FORBIDDEN");
  });

  it("calls next(AuthError[AUTH_UNAUTHORIZED]) when req.user is not set", () => {
    const authorize = createAuthorizePermissionsMiddleware(["users:read"]);

    authorize(makeReq(undefined), makeRes(), next as NextFunction);

    const arg = next.mock.calls[0]?.[0] as AuthError;
    expect(arg).toBeInstanceOf(AuthError);
    expect(arg.code).toBe("AUTH_UNAUTHORIZED");
  });
});
