# Configuration

```ts
import { createAuth, createInMemoryRevocationStore } from "@0-auth/zero-auth";

const store = createInMemoryRevocationStore(); // Replace with Redis in production.

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  refreshStore: store,
  jwt: {
    issuer: "https://api.example.com",
    audience: "web-app",
    clockTolerance: 5,
  },
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
  csrf: {
    cookieName: "csrf_token",
    headerName: "x-csrf-token",
    methods: ["POST", "PUT", "PATCH", "DELETE"],
  },
  refreshOptions: {
    rotate: true,
  },
});
```

`jwt.issuer` and `jwt.audience` are added to newly signed tokens and required
when verifying access or refresh tokens. `clockTolerance` allows a small amount
of clock skew in seconds; keep it low. Tokens with an `nbf` claim are checked by
the underlying JWT verifier.

## Required secrets

- Both secrets must be at least 32 characters.
- Use different secrets for access and refresh tokens.
- Load secrets from your deployment secret manager, not source control.

## Expiration values

Expiration values can be strings such as `15m`, `1h`, `7d`, and `30d`, or a
number of milliseconds.

The default access lifetime is `15m`; the default refresh lifetime is `7d`.
Keep access tokens short-lived and choose a refresh lifetime appropriate for
your session policy.

## Cookies

`httpOnly` is enforced for security. Use `secure: true` in production and pick
`sameSite: "strict"` when your application does not need cross-site requests.
Cookie names, paths, and domains must match the routes that receive them. See
the [cookie guide](/guides/cookies) for browser credentials and CSRF setup.

## CSRF

CSRF is opt-in and applies only when `auth.csrf()` is mounted. It protects the
configured methods when an access or refresh auth cookie is present. The
client-readable CSRF token is created with `auth.csrfToken(res)` and copied
into the configured header. See [CSRF protection](/guides/cookies#csrf-protection).

## Refresh options

| Option | Default | Purpose |
| --- | --- | --- |
| `rotate` | `false` | Issue a new refresh token on every refresh. |
| `refreshStore` | — | Atomic store wired to rotation automatically. |
| `consumeRefreshToken` | — | Atomically mark the old `jti` as used. Required for safe rotation. |
| `registerRefreshToken` | — | Track the replacement `jti` for family revocation. |
| `onRefreshReuse` | — | Revoke the token family after a replay is detected. |
| `isRevoked` / `revokeRefreshToken` | — | Legacy compatibility hooks; warn and are not concurrency-safe. |

Use a shared store for multiple instances. The [refresh rotation guide](/guides/refresh-rotation)
shows the expected lifecycle and the public `RefreshTokenStore` contract.

## Errors

Register the error handler after all routes:

```ts
app.use(auth.errorHandler);
```

Errors have a stable `code`, human-readable `message`, and HTTP `statusCode`.
Use `isAuthError(error)` when handling errors manually.

For the complete type-level reference, see the generated
[API documentation](/api/).
