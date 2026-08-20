import type { Request, Response, NextFunction, ErrorRequestHandler } from "express";
import { AuthError } from "./authErrors.js";

/**
 * Express error-handling middleware for `AuthError` instances.
 *
 * Mount this **after** all routes to ensure auth errors are caught and
 * returned as structured JSON responses.
 *
 * @example
 * ```ts
 * app.use(authErrorHandler);
 * // or use the shorthand:
 * app.use(auth.errorHandler);
 * ```
 */
export const authErrorHandler: ErrorRequestHandler = (
  err: unknown,
  _req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (err instanceof AuthError) {
    res.status(err.statusCode).json(err.toJSON());
    return;
  }

  // Pass non-auth errors to the next error handler.
  next(err);
};
