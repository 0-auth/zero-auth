import { describe, it, expect, vi } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { authErrorHandler } from "../../src/errors/errorHandler.js";
import { AuthError } from "../../src/errors/authErrors.js";

describe("authErrorHandler middleware", () => {
  it("formats and responds with JSON for AuthError instances", () => {
    const statusSpy = vi.fn().mockReturnThis();
    const jsonSpy = vi.fn();
    const res = { status: statusSpy, json: jsonSpy } as unknown as Response;
    const next = vi.fn();

    const error = new AuthError("AUTH_FORBIDDEN", "You cannot access this resource.");

    authErrorHandler(error, {} as Request, res, next as NextFunction);

    expect(statusSpy).toHaveBeenCalledWith(403);
    expect(jsonSpy).toHaveBeenCalledWith({
      error: {
        code: "AUTH_FORBIDDEN",
        message: "You cannot access this resource.",
        statusCode: 403,
      },
    });
    expect(next).not.toHaveBeenCalled();
  });

  it("passes non-AuthError instances to the next error handler", () => {
    const res = { status: vi.fn(), json: vi.fn() } as unknown as Response;
    const next = vi.fn();
    const genericError = new Error("Database connection lost");

    authErrorHandler(genericError, {} as Request, res, next as NextFunction);

    expect(next).toHaveBeenCalledWith(genericError);
    expect(res.status).not.toHaveBeenCalled();
  });
});
