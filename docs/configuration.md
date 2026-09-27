# Configuration

```ts
import { createAuth, createInMemoryRevocationStore } from "@0-auth/zero-auth";

const store = createInMemoryRevocationStore(); // Replace with Redis in production.

const auth = createAuth({
  // 1. Symmetric Secrets (Default)
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,

  // Or 2. Asymmetric Keys (RS256, ES256, EdDSA, PS256)
  // algorithm: "RS256",
  // privateKey: process.env.JWT_PRIVATE_KEY, // PKCS#8 PEM or CryptoKey
  // publicKey: process.env.JWT_PUBLIC_KEY,   // SPKI PEM or CryptoKey (required)
  // keyId: "auth-key-2026-v1",                // Optional 'kid' header claim

  // Or 3. Remote JWKS Verification (Verifier-Only Mode)
  // jwksUri: "https://auth.example.com/.well-known/jwks.json",
  // jwks: {
  //   cacheMaxAge: 600_000,     // 10 minutes cache
  //   cooldownDuration: 30_000, // 30 seconds cooldown between rate-limited refetches
  //   timeoutDuration: 5_000,   // 5 seconds fetch timeout
  // },

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

## Key Modes

`zero-auth` supports three key configurations:

1. **Symmetric Mode (`HS256`, `HS384`, `HS512`)**:
   - Requires `accessSecret` and `refreshSecret` (minimum 32 characters each).
   - Fast, shared-secret signing and verification for single services.

2. **Asymmetric Key Mode (`RS256`, `ES256`, `EdDSA`, `PS256`)**:
   - Requires `publicKey` (SPKI PEM or CryptoKey).
   - Requires `privateKey` (PKCS#8 PEM or CryptoKey) to issue tokens; omit `privateKey` for static verifier-only mode.
   - Optional `keyId` sets the `kid` header claim in signed JWTs.
   - Serves standard JWKS with `auth.jwksHandler()`.

3. **Remote JWKS Mode (`jwksUri`)**:
   - Dynamic verifier-only mode for downstream microservices and third-party IDPs (Clerk, Auth0, Firebase, Google, Cognito).
   - Zero private keys; automatically fetches and caches verification keys from `/.well-known/jwks.json`.
   - Tunable caching (`cacheMaxAge`), cooldown (`cooldownDuration`), and timeouts (`timeoutDuration`).

See the [Asymmetric Keys & Remote JWKS guide](/guides/asymmetric-and-jwks) for full architecture examples.

## Required secrets (Symmetric)

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
| `resolveUser` | — | Reload current claims; return `null` to reject the account. |
| `refreshStore` | — | Atomic store wired to rotation automatically. |
| `consumeRefreshToken` | — | Atomically mark the old `jti` as used. Required for safe rotation. |
| `registerRefreshToken` | — | Track the replacement `jti` for family revocation. |
| `onRefreshReuse` | — | Revoke the token family after a replay is detected. |
| `isRevoked` / `revokeRefreshToken` | — | Legacy compatibility hooks; warn and are not concurrency-safe. |

The claims returned by `resolveUser(claims, context)` replace the older application
claims while preserving the verified user and token-family identities.

Use a shared store for multiple instances. The [refresh rotation guide](/guides/refresh-rotation)
shows the expected lifecycle, the public `RefreshTokenStore` contract, and the
built-in `createRedisRevocationStore()` adapter for ioredis-compatible clients.

## Errors

Register the error handler after all routes:

```ts
app.use(auth.errorHandler);
```

Errors have a stable `code`, human-readable `message`, and HTTP `statusCode`.
Use `isAuthError(error)` when handling errors manually.

For the complete type-level reference, see the generated
[API documentation](/api/).
