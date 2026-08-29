# Error reference

`zero-auth` returns structured errors with the same shape for middleware,
refresh, and manual token operations.

```json
{
  "error": {
    "code": "AUTH_TOKEN_EXPIRED",
    "message": "Authentication token has expired.",
    "statusCode": 401
  }
}
```

## Error codes

| Code | HTTP status | What it means | What to check |
| --- | :---: | --- | --- |
| `AUTH_TOKEN_MISSING` | `401` | No access token was found. | Send `Authorization: Bearer <token>` or configure/send the auth cookie. |
| `AUTH_TOKEN_INVALID` | `401` | The token is malformed, has the wrong signature, or was revoked. | Check that the complete token is sent and that access/refresh secrets match the issuer. |
| `AUTH_TOKEN_EXPIRED` | `401` | The token passed its expiration time. | Refresh the session or sign in again. |
| `AUTH_UNAUTHORIZED` | `401` | The request is not authenticated. | Run `protect()` before code that needs `req.user`. |
| `AUTH_FORBIDDEN` | `403` | The user is authenticated but lacks the required role or permission. | Check `req.user.role`, `req.user.permissions`, and the authorization middleware. |
| `AUTH_CSRF_INVALID` | `403` | Auth cookies are present but the CSRF token is missing or invalid. | Send the token returned by `auth.csrfToken(res)` in the configured header and keep the matching CSRF cookie. |

## Express error handling

Register the built-in handler after all routes:

```ts
app.use(auth.errorHandler);
```

This turns `AuthError` instances into the JSON response shown above.

## Manual handling

Use `isAuthError()` when you need to customize logging or the response:

```ts
import { isAuthError } from "@0-auth/zero-auth";

try {
  const payload = await auth.verifyToken(token);
  return res.json({ payload });
} catch (error) {
  if (isAuthError(error)) {
    console.warn("Authentication failed", {
      code: error.code,
      statusCode: error.statusCode,
    });
    return res.status(error.statusCode).json(error.toJSON());
  }

  return next(error);
}
```

## Common fixes

### Every request returns `AUTH_TOKEN_MISSING`

Check the header spelling and ensure the access token is not the refresh token:

```http
Authorization: Bearer eyJ...
```

For cookies, check the cookie path, domain, `secure` flag, and whether the
browser request includes credentials.

### Tokens are always invalid

Use the same `accessSecret` when signing and verifying access tokens. Keep the
`refreshSecret` separate and do not use it for access-token requests.

### Admin requests return `AUTH_FORBIDDEN`

`authorize()` checks `req.user.role`. Make sure the role is included in the
token payload and that `protect()` runs first:

```ts
app.get("/admin", auth.protect(), auth.authorize(["admin"]), handler);
```

For permission checks, confirm every required permission is present:

```ts
app.get(
  "/users",
  auth.protect(),
  auth.authorizePermissions(["users:read"]),
  handler,
);
```

### Cookie writes return `AUTH_CSRF_INVALID`

Mount `auth.csrf()` before the state-changing routes, request a token from a
same-origin endpoint, and send the returned value in the configured header.
Check that the browser includes credentials and that the CSRF cookie has not
been overwritten by a different path or domain.

### Refresh requests return `AUTH_TOKEN_INVALID`

With rotation enabled, a refresh token is single-use. Confirm that concurrent
clients do not refresh the same token and that the replacement token is saved
after a successful response. If the revocation store is unavailable, the
handler fails closed and the client should sign in again or retry according to
the application's availability policy.
