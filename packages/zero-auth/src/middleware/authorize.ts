import type { Request, Response, NextFunction, RequestHandler } from "express";
import { AuthError } from "../errors/authErrors.js";
import { logger } from "../utils/logger.js";

/**
 * Returns an Express middleware that enforces role-based access control.
 *
 * Must be used **after** `auth.protect()` so that `req.user` is already set.
 * Passes if the authenticated user's `role` is in the `allowedRoles` array.
 * Throws `AUTH_FORBIDDEN` (403) otherwise.
 *
 * @param allowedRoles - Array of role strings that are permitted.
 *
 * @example
 * ```ts
 * app.delete(
 *   "/admin/users/:id",
 *   auth.protect(),
 *   auth.authorize(["admin", "superadmin"]),
 *   deleteUserHandler
 * );
 * ```
 */
export function createAuthorizeMiddleware(allowedRoles: string[]): RequestHandler {
  if (allowedRoles.length === 0) {
    throw new Error("[zero-auth] `authorize()` requires at least one role.");
  }

  return function authorize(req: Request, _res: Response, next: NextFunction): void {
    const user = req.user;

    if (!user) {
      // Defensive: protect() should always run first.
      logger.warn("authorize: called without req.user set — is auth.protect() mounted first?");
      next(new AuthError("AUTH_UNAUTHORIZED"));
      return;
    }

    const userRole = user.role;

    if (!userRole || !allowedRoles.includes(userRole)) {
      logger.debug(
        `authorize: role "${userRole ?? "none"}" not in [${allowedRoles.join(", ")}] for user ${user.id}`
      );
      next(new AuthError("AUTH_FORBIDDEN"));
      return;
    }

    logger.debug(`authorize: role "${userRole}" authorized for user ${user.id}`);
    next();
  };
}

/**
 * Returns an Express middleware that requires every listed user permission.
 *
 * Must be used **after** `auth.protect()` so that `req.user` is already set.
 * Throws `AUTH_FORBIDDEN` (403) when any permission is missing.
 *
 * @param requiredPermissions - Permission strings the user must have.
 *
 * @example
 * ```ts
 * app.get(
 *   "/users",
 *   auth.protect(),
 *   auth.authorizePermissions(["users:read"]),
 *   listUsersHandler
 * );
 * ```
 */
export function createAuthorizePermissionsMiddleware(
  requiredPermissions: string[]
): RequestHandler {
  if (requiredPermissions.length === 0) {
    throw new Error("[zero-auth] `authorizePermissions()` requires at least one permission.");
  }

  return function authorizePermissions(req: Request, _res: Response, next: NextFunction): void {
    const user = req.user;

    if (!user) {
      logger.warn(
        "authorizePermissions: called without req.user set — is auth.protect() mounted first?"
      );
      next(new AuthError("AUTH_UNAUTHORIZED"));
      return;
    }

    const userPermissions = user.permissions;

    if (
      !Array.isArray(userPermissions) ||
      !requiredPermissions.every((permission) => userPermissions.includes(permission))
    ) {
      logger.debug(`authorizePermissions: missing permission for user ${user.id}`);
      next(new AuthError("AUTH_FORBIDDEN"));
      return;
    }

    logger.debug(`authorizePermissions: user ${user.id} authorized`);
    next();
  };
}
