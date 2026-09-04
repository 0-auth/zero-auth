# @0-auth/zero-auth

Minimal JWT authentication for Node.js and Express APIs.

No database. No hosted auth service. Just access tokens, refresh-token rotation,
HTTP-only cookies, and RBAC with middleware your team can understand.

## ⚠️ Attention — Breaking Changes & Upgrade Notes

> [!NOTE]
> Any release with breaking changes will list them in this section before the
> rest of the README. Legacy `isRevoked` + `revokeRefreshToken` hooks remain
> supported for compatibility, but emit a warning and are not concurrency-safe.
> Use the atomic `consumeRefreshToken` hook for rotated refresh tokens,
> especially in multi-instance deployments. The new `RefreshTokenStore` API is
> the recommended integration for shared rotation state.

**Start here:** [5-minute quick start](#quick-start-5-minutes) · [runnable examples](#examples) · [API reference](#api-reference)

**Documentation:** [zero-auth.netlify.app](https://zero-auth.netlify.app/) ·
[guides](https://zero-auth.netlify.app/v1/) ·
[API reference](https://zero-auth.netlify.app/v1/api/)

[![npm version](https://img.shields.io/npm/v/@0-auth/zero-auth.svg)](https://www.npmjs.com/package/@0-auth/zero-auth)
[![npm downloads](https://img.shields.io/npm/dm/@0-auth/zero-auth.svg)](https://www.npmjs.com/package/@0-auth/zero-auth)
[![CI](https://github.com/0-auth/zero-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/0-auth/zero-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)

> **JWT auth with refresh-token rotation and reuse detection** for teams that
> want to keep identity and storage in their own application.

---

## Table of Contents

- [Features](#features)
- [Scope](#scope)
- [Security model](#security-model)
- [Installation](#installation)
- [Quick Start (5 Minutes)](#quick-start-5-minutes)
- [Examples](#examples)
- [Configuration Options](#configuration-options)
  - [Usage Guides](#usage-guides)
  - [1. Header / Bearer Token Auth](#1-header--bearer-token-auth)
  - [2. HTTP-Only Cookie Auth](#2-http-only-cookie-auth)
  - [CSRF Protection for Cookie Auth](#csrf-protection-for-cookie-auth)
  - [3. Route Protection & RBAC](#3-route-protection--rbac)
  - [4. Optional Authentication](#4-optional-authentication)
  - [5. Token Refresh & Rotation](#5-token-refresh--rotation)
- [Error Handling & Error Codes](#error-handling--error-codes)
- [TypeScript Support](#typescript-support)
- [API Reference](#api-reference)
  - [Instance Methods (`auth.*`)](#instance-methods-auth)
  - [Standalone Utilities](#standalone-utilities)
- [Production & Security Best Practices](#production--security-best-practices)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **JWT Validation Policy**: Optionally enforce token issuer, audience, clock tolerance, and `nbf` validation.
- **Pluggable Refresh Stores**: Connect atomic refresh-token consumption and family revocation to Redis or another store.
- ⚡ **Zero-Boilerplate Setup**: Initialize with `createAuth()` and start securing routes immediately.
- 🔒 **Secure by Default**: Cryptographically signed tokens (HS256 via [jose](https://github.com/panva/jose)), enforced minimum 32-character secret length.
- 🍪 **Built-in Cookie Support**: Seamless HTTP-only cookie handling without extra cookie middleware dependencies.
- 🛡️ **Cookie CSRF Protection**: Signed double-submit middleware for state-changing cookie requests.
- 🔄 **Automatic Token Refresh & Rotation**: Built-in refresh route handler with optional token family reuse detection.
- 🛡️ **Role-Based Access Control (RBAC)**: Flexible role-checking middleware (`auth.authorize(['admin', 'editor'])`).
- 🔑 **Permission-Based Access Control**: Require fine-grained permissions with `auth.authorizePermissions(['users:read'])`.
- 🧩 **First-Class TypeScript**: Automatic `req.user` typing via declaration merging with support for custom claims.
- 🛑 **Structured Error Handling**: Standardized `AuthError` class with typed error codes (`AUTH_TOKEN_EXPIRED`, `AUTH_FORBIDDEN`, etc.).
- 🌐 **Modern & Edge-Ready**: Dual ESM & CommonJS builds, Node 18+, Bun, serverless, and edge runtime compatible.

---

## Scope

`zero-auth` is an authentication layer, not a complete identity platform. It
does not provide a user database, password hashing, OAuth providers, email
verification, password reset, MFA, or user-management UI. Your application
owns those decisions and supplies the user identity used in token claims.

---

## Security model

| Concern | Default approach |
| --- | --- |
| Access tokens | Short-lived JWTs, typically `15m` |
| Refresh tokens | Longer-lived tokens, typically `7d` |
| Rotation | Enable `refreshOptions.rotate` when replay detection matters |
| Revocation | Your Redis, database, or other application store |
| Browser storage | HTTP-only cookies when a cookie flow is appropriate |

`zero-auth` does not choose or manage your user database. Read the full
[security checklist](https://zero-auth.netlify.app/v1/security) before deploying
to production.

---

## Installation

```bash
npm install @0-auth/zero-auth
# or
yarn add @0-auth/zero-auth
# or
pnpm add @0-auth/zero-auth
```

> **Note:** If using Express middleware, install `express` (peer dependency):
> ```bash
> npm install express
> ```

---

## Quick Start (5 Minutes)

Here is a complete, copy-pasteable Express application using `zero-auth`:

Set `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` to different random values of
at least 32 characters before starting the app.

```ts
import express from "express";
import { createAuth } from "@0-auth/zero-auth";

// 1. Initialize Auth instance
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",
});

const app = express();
app.use(express.json());

// 2. Login Route (generates and sends token pair or cookies)
app.post("/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    // ... validate credentials against your database ...
    const userPayload = { id: "user-123", email, role: "admin" };

    // Option A: Set HTTP-Only cookies + return tokens
    const tokens = await auth.sendAuthTokens(res, userPayload);
    res.json({ message: "Logged in successfully", tokens });

    // Option B (Bearer only): const tokens = await auth.generateTokenPair(userPayload); res.json(tokens);
  } catch (err) {
    next(err);
  }
});

// 3. Protected Route (requires valid access token)
app.get("/api/profile", auth.protect(), (req, res) => {
  // req.user is automatically typed as AuthUser!
  res.json({ user: req.user });
});

// 4. Role-Restricted Route (Admin only)
app.get("/api/admin/dashboard", auth.protect(), auth.authorize(["admin"]), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user?.id}` });
});

// 5. Refresh Token Route
app.post("/auth/refresh", auth.refreshHandler());

// 6. Logout Route (clears HTTP-Only cookies)
app.post("/auth/logout", (req, res) => {
  auth.clearAuth(res);
  res.json({ message: "Logged out successfully" });
});

// 7. Error handling middleware (must be registered after routes)
app.use(auth.errorHandler);

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
```

---

## Examples

Two complete, runnable example projects are included in the
[`examples/`](https://github.com/0-auth/zero-auth/tree/master/examples) directory:

| Example | Description | Features |
| ------- | ----------- | -------- |
| [`express-rest-api`](https://github.com/0-auth/zero-auth/tree/master/examples/express-rest-api) | Stateless Bearer token API for mobile / CLI / SPA clients | `generateTokenPair`, `protect`, `authorize`, `optional`, `refreshHandler`, `decodeToken` |
| [`express-cookies-redis`](https://github.com/0-auth/zero-auth/tree/master/examples/express-cookies-redis) | Cookie-based auth with Redis-backed refresh token rotation | `sendAuthTokens`, `clearAuth`, CSRF, rotation hooks, family revocation, `onRefreshReuse` |

Each example includes a README with setup instructions and cURL commands for every endpoint.

For the complete documentation map, read the
[documentation site](https://zero-auth.netlify.app/v1/). It covers bearer and
cookie clients, CSRF, roles and permissions, refresh rotation, errors,
deployment, testing, versioning, and releases.

```bash
# Quick start (REST API example)
cd examples/express-rest-api
npm install
npm start
```

---

## Configuration Options

Pass your settings to `createAuth(config)`:

```ts
const auth = createAuth({
  // Required
  accessSecret: process.env.JWT_ACCESS_SECRET!,   // String (min 32 chars)
  refreshSecret: process.env.JWT_REFRESH_SECRET!, // String (min 32 chars, distinct from accessSecret)

  // Optional JWT validation policy
  jwt: {
    issuer: "https://api.example.com",
    audience: "web-app",
    clockTolerance: 5, // Allowed clock skew in seconds
  },

  // Optional Token Expirations (defaults shown)
  accessExpiresIn: "15m",   // Formats: "15m", "1h", "7d", "30d", or milliseconds
  refreshExpiresIn: "7d",

  // Optional Cookie Configuration
  cookies: {
    accessTokenName: "access_token",   // Cookie name for access token
    refreshTokenName: "refresh_token", // Cookie name for refresh token
    options: {
      httpOnly: true,        // Always enforced as true for security
      secure: true,          // Defaults to true when NODE_ENV === 'production'
      sameSite: "lax",       // 'lax' | 'strict' | 'none'
      path: "/",             // Cookie path
      domain: undefined,     // Optional cookie domain
    },
  },

  // Optional CSRF protection for cookie-authenticated requests
  csrf: {
    cookieName: "csrf_token",       // Client-readable token cookie
    headerName: "x-csrf-token",     // Header copied from that cookie
    methods: ["POST", "PUT", "PATCH", "DELETE"],
  },

  // Optional Refresh Rotation & Revocation
  refreshOptions: {
    rotate: false,           // Set to true to enable Refresh Token Rotation
    // Required when rotate: true: implement an atomic single-use check.
    // consumeRefreshToken: (oldJti, ctx) => redis.set(..., { NX: true }).then(result => result === "OK"),
    registerRefreshToken: async (newJti, ctx) => {},
    onRefreshReuse: async (ctx) => {},
  },
});
```

When configured, `jwt.issuer` and `jwt.audience` are included in new tokens and
must match during verification. `clockTolerance` allows limited clock skew in
seconds. JWT `nbf` claims are also validated automatically.

---

## Usage Guides

### 1. Header / Bearer Token Auth

For mobile apps, CLI tools, or traditional REST APIs sending tokens via headers:

```ts
// Login: Return raw tokens in JSON response
app.post("/auth/login", async (req, res) => {
  const tokens = await auth.generateTokenPair({
    id: "user_123",
    email: "user@example.com",
    role: "user",
  });

  res.json(tokens);
  // { accessToken: "eyJ...", refreshToken: "eyJ..." }
});

// Client sends: Authorization: Bearer <accessToken>
app.get("/api/data", auth.protect(), (req, res) => {
  res.json({ data: "Protected content", userId: req.user.id });
});
```

---

### 2. HTTP-Only Cookie Auth

For web applications (SPAs, React, Next.js, Vue) to protect against XSS token theft:

```ts
// Login: Sets secure HTTP-Only cookies on the response automatically
app.post("/auth/login", async (req, res) => {
  const user = { id: "user_123", role: "member" };
  const tokens = await auth.sendAuthTokens(res, user);
  res.json({ user, tokens });
});

// Protected routes automatically read tokens from either Cookie or Authorization header
app.get("/api/data", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

// Logout: Clears both cookies using the exact same path and options
app.post("/auth/logout", (req, res) => {
  auth.clearAuth(res);
  res.json({ message: "Logged out" });
});
```

### CSRF Protection for Cookie Auth

Cookie-authenticated state-changing requests should include a CSRF token. Add
the middleware before your routes and expose a small same-origin endpoint that
sets and returns the client-readable token:

```ts
app.use(auth.csrf());

app.get("/auth/csrf-token", (req, res) => {
  res.json({ csrfToken: auth.csrfToken(res) });
});

app.post("/api/profile", auth.protect(), (req, res) => {
  res.json({ updated: true, user: req.user });
});
```

The browser sends the token in the configured header on `POST`, `PUT`, `PATCH`,
and `DELETE` requests:

```ts
const { csrfToken } = await fetch("/auth/csrf-token", {
  credentials: "include",
}).then((response) => response.json());

await fetch("/api/profile", {
  method: "POST",
  credentials: "include",
  headers: { "x-csrf-token": csrfToken },
});
```

Requests without auth cookies and safe methods such as `GET` pass through. The
middleware does not protect bearer-token requests because browsers do not send
their `Authorization` header automatically. Mount `app.use(auth.csrf())`
before state-changing routes, and keep `app.use(auth.errorHandler)` last.

---

### 3. Route Protection & RBAC

Protect routes and limit access by user roles:

```ts
// Single role requirement
app.get("/admin", auth.protect(), auth.authorize(["admin"]), adminHandler);

// Multiple allowed roles (user must have at least one)
app.get(
  "/reports",
  auth.protect(),
  auth.authorize(["admin", "manager", "auditor"]),
  reportsHandler
);
```

> **Note:** `auth.authorize()` checks `req.user.role`. Always place `auth.protect()` before `auth.authorize()` in the middleware chain.

For fine-grained access checks, require every permission listed in the user's
`permissions` claim:

```ts
app.get(
  "/users",
  auth.protect(),
  auth.authorizePermissions(["users:read"]),
  listUsersHandler
);
```

`auth.authorizePermissions()` also requires `auth.protect()` first and returns
`AUTH_FORBIDDEN` when any required permission is missing.

---

### 4. Optional Authentication

Use `auth.optional()` for endpoints that serve both guests and authenticated users (e.g. public articles with personalized like buttons):

```ts
app.get("/articles/:slug", auth.optional(), (req, res) => {
  if (req.user) {
    // Authenticated user
    res.json({ article: getArticle(), bookmarked: true });
  } else {
    // Guest visitor (req.user is undefined)
    res.json({ article: getArticle(), bookmarked: false });
  }
});
```

---

### 5. Token Refresh & Rotation

`zero-auth` includes a ready-to-use Express handler for refreshing tokens:

```ts
app.post("/auth/refresh", auth.refreshHandler());
```

**How the refresh token is extracted:**
1. Refresh token cookie (`cookies.refreshTokenName`)
2. JSON body field (`refreshToken` or `refresh_token`)
3. `Authorization: Bearer <refreshToken>` header

#### Advanced: Refresh Token Rotation (with Redis)

When `refreshOptions.rotate: true` is enabled, a new refresh token is issued on every refresh request, and old tokens are invalidated. If an old token is reused (indicating a stolen token), `onRefreshReuse` is triggered to invalidate the entire token family.

`consumeRefreshToken` should atomically mark the incoming `jti` as consumed and
return `false` when it was already consumed. Use a Redis `SET NX` or equivalent
database conditional write when the application runs on multiple instances.
You can pass a public `refreshStore` instead; its atomic `consume()` method and
optional `register()` / `revokeFamily()` methods are wired into rotation
automatically. Explicit refresh hooks still take precedence.
The legacy `isRevoked` + `revokeRefreshToken` pair remains supported for
compatibility, but logs a warning and is not concurrency-safe.

Install `ioredis` in your application, then use the built-in adapter. The
package does not add a Redis client dependency to your application:

```bash
npm install @0-auth/zero-auth ioredis
```

```ts
import Redis from "ioredis";
import {
  createAuth,
  createRedisRevocationStore,
} from "@0-auth/zero-auth";

const redis = new Redis(process.env.REDIS_URL);
const refreshStore = createRedisRevocationStore(redis);

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  refreshStore,
  refreshOptions: {
    rotate: true,
    onRefreshReuse: async ({ familyId }) => {
      if (familyId) await refreshStore.revokeFamily(familyId);
    },
  },
});
```

The adapter uses Redis `SET NX` for atomic single-use consumption and tracks
refresh-token families with TTLs. It accepts the ioredis-compatible client
surface without importing or bundling a Redis client. When a family is
compromised, it writes a marker before scanning known members and atomically
rejects late replacement registrations, so a concurrent replay cannot leave a
new usable refresh token behind.

---

## Error Handling & Error Codes

All errors thrown by `zero-auth` are instances of `AuthError`.

### Built-in Error Handler Middleware

```ts
// Mount after all routes
app.use(auth.errorHandler);
```

Default JSON error response format:
```json
{
  "error": {
    "code": "AUTH_TOKEN_EXPIRED",
    "message": "Token has expired",
    "statusCode": 401
  }
}
```

### Manual Error Handling

```ts
import { isAuthError, AuthError, AUTH_ERROR_CODES } from "@0-auth/zero-auth";

try {
  const payload = await auth.verifyToken(tokenString);
} catch (err) {
  if (isAuthError(err)) {
    console.error(`Auth failed [${err.code}]: ${err.message} (HTTP ${err.statusCode})`);
  }
}
```

### Standard Error Codes

| Code | Status Code | Description |
|---|:---:|---|
| `AUTH_TOKEN_MISSING` | `401` | No authentication token found in request headers or cookies. |
| `AUTH_TOKEN_INVALID` | `401` | Token is malformed or signature verification failed. |
| `AUTH_TOKEN_EXPIRED` | `401` | Token has exceeded its expiration time. |
| `AUTH_UNAUTHORIZED` | `401` | General unauthenticated error (e.g. invalid credentials or missing user state). |
| `AUTH_FORBIDDEN` | `403` | User is authenticated but does not possess the required role or permission. |
| `AUTH_CSRF_INVALID` | `403` | Auth cookies are present but the CSRF token is missing or invalid. |

---

## TypeScript Support

`zero-auth` automatically augments Express's `Request` type with `req.user`.

```ts
import type { AuthUser } from "@0-auth/zero-auth";

interface AuthUser {
  id: string;
  email?: string;
  role?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  jti?: string;
  fid?: string; // Token family ID (when rotation is enabled)
  [key: string]: unknown; // Custom claims
}
```

Custom claims in your JWT payload are preserved across token refreshes and are typed on `req.user`:

```ts
// Sign with custom claims
await auth.generateAccessToken({
  id: "user_123",
  role: "admin",
  tenantId: "tenant_abc",
});

// In route handler
app.get("/tenant", auth.protect(), (req, res) => {
  const tenantId = req.user.tenantId; // accessible
  res.json({ tenantId });
});
```

---

## API Reference

### Instance Methods (`auth.*`)

Created via `const auth = createAuth(config)`:

| Method | Return Type | Description |
|---|---|---|
| `generateAccessToken(payload)` | `Promise<string>` | Generates a signed access token. |
| `generateRefreshToken(payload)` | `Promise<string>` | Generates a signed refresh token. |
| `generateTokenPair(payload)` | `Promise<{ accessToken, refreshToken }>` | Generates both access and refresh tokens in parallel. |
| `verifyToken(token)` | `Promise<AuthUser>` | Verifies access token signature and expiration. |
| `verifyRefreshToken(token)` | `Promise<AuthUser>` | Verifies refresh token signature and expiration. |
| `decodeToken(token)` | `AuthUser` | Decodes a token **without** verifying signature. |
| `protect()` | `RequestHandler` | Express middleware: rejects requests without valid access token (401). |
| `authorize(roles)` | `RequestHandler` | Express middleware: ensures `req.user.role` is in allowed roles (403). |
| `authorizePermissions(permissions)` | `RequestHandler` | Express middleware: requires every listed permission in `req.user.permissions` (403). |
| `optional()` | `RequestHandler` | Express middleware: sets `req.user` if valid token present, allows guests. |
| `csrf()` | `RequestHandler` | Express middleware: validates CSRF tokens on configured methods when auth cookies are present. |
| `sendAuthTokens(res, payload)` | `Promise<TokenPair>` | Sets access + refresh HTTP-only cookies on `res` and returns tokens. |
| `clearAuth(res)` | `void` | Clears access and refresh auth cookies from `res`. |
| `csrfToken(res)` | `string` | Sets and returns a client-readable signed CSRF token. |
| `refreshHandler()` | `RequestHandler` | Express route handler for refreshing access tokens. |
| `rotateTokens(payload)` | `Promise<TokenPair>` | Generates a new access + refresh pair (for custom rotation logic). |
| `errorHandler` | `ErrorRequestHandler` | Express error middleware for handling `AuthError` responses. |

---

### Standalone Utilities

All core helpers are also exported directly for custom architectures:

```ts
import {
  // Token Helpers
  signToken,
  verifyToken,
  decodeToken,

  // Extractors
  extractToken,
  extractRefreshToken,

  // Cookie Utilities
  setCookie,
  clearCookie,
  parseCookieHeader,

  // Error Helpers
  AuthError,
  isAuthError,
  authErrorHandler,

  // In-Memory Revocation (Testing / Dev)
  createInMemoryRevocationStore,
  // Redis-backed revocation (distributed deployments)
  createRedisRevocationStore,
} from "@0-auth/zero-auth";
```

| Utility | Description |
|---|---|
| `signToken(payload, secret, options)` | Low-level JWT signing function using `jose`. |
| `verifyToken(token, secret)` | Low-level JWT verification function. |
| `decodeToken(token)` | Unsafely decodes token payload without signature verification. |
| `extractToken(req, cookieName?)` | Extracts access token from `Authorization` header or cookie. |
| `extractRefreshToken(req, cookieName?)` | Extracts refresh token from cookie, body, or header. |
| `setCookie(res, name, value, options)` | Sets an HTTP-only cookie with secure defaults. |
| `clearCookie(res, name, options)` | Clears a cookie matching its path/domain/sameSite settings. |
| `parseCookieHeader(cookieHeader)` | Zero-dependency cookie string parser. |
| `createInMemoryRevocationStore()` | In-memory token revocation helper for development and tests. |
| `createRedisRevocationStore(redis, ttlSeconds?)` | ioredis-compatible store for atomic rotation and family revocation. |

---

## Production & Security Best Practices

1. **Secret Keys**:
   - Always supply separate `accessSecret` and `refreshSecret` values with a minimum length of 32 characters.
   - Generate secure keys using:
     ```bash
     node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
     ```
2. **HTTPS & Cookies**:
   - In production (`NODE_ENV=production`), `secure: true` is automatically enabled on cookies so tokens are only transmitted over HTTPS.
   - HTTP-only cookies prevent client-side JavaScript access, neutralizing XSS token theft.
   - Mount `auth.csrf()` for cookie-authenticated state-changing requests and send the token in the configured header.
3. **Token Lifespans**:
   - Keep `accessExpiresIn` short (`15m` recommended).
   - Refresh tokens can have longer lifespans (`7d` - `30d`).
4. **Token Revocation in Distributed Systems**:
   - Use Redis or your primary database with TTLs to track revoked `jti` identifiers when `refreshOptions.rotate: true` is enabled.
5. **Abuse Prevention**:
   - Rate-limit login, registration, refresh, and password-reset endpoints.
   - Use an allow-listed CORS policy for browser clients.
   - Monitor authentication failures, refresh replays, and revocation-store errors.

---

## Compatibility

| Environment | Supported | Notes |
|---|:---:|---|
| **Node.js** | >= 18.0.0 | Full ESM & CommonJS support |
| **Express** | 4.x & 5.x | Peer dependency for middleware |
| **Bun** | >= 1.0.0 | Native runtime support |
| **TypeScript** | >= 5.0.0 | Declarations bundled |
| **Serverless / Edge** | ✅ | Powered by `jose` (Web Crypto API compliant) |

The npm tarball includes the README, CHANGELOG, license, compiled ESM/CommonJS
builds, and TypeScript declarations. The full guide and generated API site are
built from the repository's `docs/` source.

---

## Contributing

Found a bug or have an idea? [Open an issue](https://github.com/0-auth/zero-auth/issues)
or read the [contribution guide](https://github.com/0-auth/zero-auth/blob/master/CONTRIBUTING.md).

---

## License

[MIT](./LICENSE) © zero-auth contributors
