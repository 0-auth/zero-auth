# Configuration

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",
  cookies: {
    accessTokenName: "access_token",
    refreshTokenName: "refresh_token",
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    },
  },
});
```

## Required secrets

- Both secrets must be at least 32 characters.
- Use different secrets for access and refresh tokens.
- Load secrets from your deployment secret manager, not source control.

## Expiration values

Expiration values can be strings such as `15m`, `1h`, `7d`, and `30d`, or a
number of milliseconds.

## Cookies

`httpOnly` is enforced for security. Use `secure: true` in production and pick
`sameSite: "strict"` when your application does not need cross-site requests.

## Errors

Register the error handler after all routes:

```ts
app.use(auth.errorHandler);
```

Errors have a stable `code`, human-readable `message`, and HTTP `statusCode`.
Use `isAuthError(error)` when handling errors manually.
