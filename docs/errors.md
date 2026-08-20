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
| `AUTH_FORBIDDEN` | `403` | The user is authenticated but lacks the required role. | Check `req.user.role` and the roles passed to `authorize()`. |

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
