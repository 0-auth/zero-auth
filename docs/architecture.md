# Architecture and request flows

zero-auth is a library inside your API process. It signs and verifies JWTs,
provides Express middleware, and calls application-owned hooks for stateful
refresh protection.

## Responsibility boundary

~~~text
Client
  │  bearer header or cookies
  ▼
Express application
  │  credential lookup, password hashing, business policy
  ▼
zero-auth
  │  sign, verify, extract, protect, authorize, refresh
  ▼
Application stores
  ├─ user database
  └─ Redis/database refresh state when rotation is enabled
~~~

The package never creates users, checks passwords, chooses a database, or
decides resource ownership. Your application supplies a trusted user payload
after its own credential checks.

## Token lifecycle

~~~text
login
  └─ application verifies credentials
      └─ zero-auth signs access + refresh tokens

API request
  └─ protect() extracts and verifies the access token
      └─ req.user is populated
          └─ authorize()/authorizePermissions() checks policy

refresh
  └─ refreshHandler() verifies the refresh token
      ├─ stateless mode: issue a new access token
      └─ rotation mode: atomically consume jti, then issue a new pair
~~~

## Claims

Application claims are preserved through refresh:

| Claim | Purpose |
| --- | --- |
| <code>id</code> | Required application user identifier |
| <code>email</code> | Optional application user email |
| <code>role</code> | Optional role checked by <code>authorize()</code> |
| <code>permissions</code> | Optional strings checked by <code>authorizePermissions()</code> |
| <code>jti</code> | Token identifier used for refresh rotation |
| <code>fid</code> | Stable refresh-token family identifier when rotation is enabled |
| <code>iss</code> / <code>aud</code> | Optional issuer and audience claims enforced by JWT policy |
| <code>iat</code> / <code>exp</code> | Issued-at and expiration timestamps |

Do not put passwords, secrets, or unnecessary sensitive data in claims. JWT
payloads are readable by anyone holding the token even though they are signed.

## Middleware ordering

~~~ts
app.use(express.json());
app.use(auth.csrf()); // Needed for cookie-authenticated writes.

app.patch(
  "/users/:id",
  auth.protect(),
  auth.authorizePermissions(["users:update"]),
  updateUserHandler,
);

app.use(auth.errorHandler); // Last.
~~~

CSRF checks whether auth cookies are present. Bearer requests still need
protect and authorization, but do not need the cookie CSRF middleware.

## Stateless and stateful modes

| Mode | Shared storage | Replay detection | Best fit |
| --- | --- | --- | --- |
| Bearer, no rotation | No | No | Simple APIs and internal services |
| Cookie, no rotation | No | No | Small browser applications |
| Rotating refresh tokens | Yes for multiple instances | Yes | Production sessions requiring replay response |

An in-memory revocation store is suitable for tests and one-process development.
Redis or a database is required when instances restart or requests can reach
different processes.

## Source layout

- <code>packages/zero-auth/src/core</code>: JWT signing, verification, and decoding.
- <code>packages/zero-auth/src/middleware</code>: protection, optional auth, roles, permissions, and CSRF.
- <code>packages/zero-auth/src/refresh</code>: refresh handling and revocation-store helpers.
- <code>packages/zero-auth/src/cookies</code>: cookie setting, clearing, and parsing.
- <code>packages/zero-auth/src/errors</code>: typed errors and Express error responses.
- <code>packages/zero-auth/src/types</code>: public configuration, payload, and Express augmentation types.
- <code>tests</code>: unit, integration, security, rotation, and concurrency coverage.

## Failure boundaries

Invalid access tokens fail with 401. Missing roles or permissions fail with
403. Invalid CSRF values fail with 403. A rotation-store failure fails closed
with 401 AUTH_TOKEN_INVALID so the server does not issue untracked tokens.
