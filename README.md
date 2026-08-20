# @wtfdrshn/zero-auth

[![npm version](https://img.shields.io/npm/v/@wtfdrshn/zero-auth.svg)](https://www.npmjs.com/package/@wtfdrshn/zero-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)

> A lightweight, developer-first JWT authentication package for Node.js and Express.  
> **JWT auth in under 5 minutes. Zero boilerplate.**

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start (5 Minutes)](#quick-start-5-minutes)
- [Configuration Options](#configuration-options)
- [Usage Guides](#usage-guides)
  - [1. Header / Bearer Token Auth](#1-header--bearer-token-auth)
  - [2. HTTP-Only Cookie Auth](#2-http-only-cookie-auth)
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
- [License](#license)

---

## Features

- ⚡ **Zero-Boilerplate Setup**: Initialize with `createAuth()` and start securing routes immediately.
- 🔒 **Secure by Default**: Cryptographically signed tokens (HS256 via [jose](https://github.com/panva/jose)), enforced minimum 32-character secret length.
- 🍪 **Built-in Cookie Support**: Seamless HTTP-only cookie handling without extra cookie middleware dependencies.
- 🔄 **Automatic Token Refresh & Rotation**: Built-in refresh route handler with optional token family reuse detection.
- 🛡️ **Role-Based Access Control (RBAC)**: Flexible role-checking middleware (`auth.authorize(['admin', 'editor'])`).
- 🧩 **First-Class TypeScript**: Automatic `req.user` typing via declaration merging with support for custom claims.
- 🛑 **Structured Error Handling**: Standardized `AuthError` class with typed error codes (`AUTH_TOKEN_EXPIRED`, `AUTH_FORBIDDEN`, etc.).
- 🌐 **Modern & Edge-Ready**: Dual ESM & CommonJS builds, Node 18+, Bun, serverless, and edge runtime compatible.

---

## Installation

```bash
npm install @wtfdrshn/zero-auth
# or
yarn add @wtfdrshn/zero-auth
# or
pnpm add @wtfdrshn/zero-auth
```

> **Note:** If using Express middleware, install `express` (peer dependency):
> ```bash
> npm install express
> ```

---

## Quick Start (5 Minutes)

Here is a complete, copy-pasteable Express application using `zero-auth`:

```ts
import express from "express";
import { createAuth } from "@wtfdrshn/zero-auth";

// 1. Initialize Auth instance
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET || "your-at-least-32-character-access-secret-key",
  refreshSecret: process.env.JWT_REFRESH_SECRET || "your-at-least-32-character-refresh-secret-key",
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",
});

const app = express();
app.use(express.json());
app.use(auth.initialize());

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

## Configuration Options

Pass your settings to `createAuth(config)`:

```ts
const auth = createAuth({
  // Required
  accessSecret: process.env.JWT_ACCESS_SECRET!,   // String (min 32 chars)
  refreshSecret: process.env.JWT_REFRESH_SECRET!, // String (min 32 chars, distinct from accessSecret)

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

  // Optional Refresh Rotation & Revocation
  refreshOptions: {
    rotate: false,           // Set to true to enable Refresh Token Rotation
    isRevoked: async (jti) => false,
    revokeRefreshToken: async (oldJti, ctx) => {},
    registerRefreshToken: async (newJti, ctx) => {},
    onRefreshReuse: async (ctx) => {},
  },
});
```

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

```ts
import { createClient } from "redis";
import { createAuth } from "@wtfdrshn/zero-auth";

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  refreshOptions: {
    rotate: true,
    // Check if token was already revoked
    isRevoked: async (jti) => {
      return (await redis.exists(`revoked:${jti}`)) === 1;
    },
    // Revoke the old token before issuing new tokens
    revokeRefreshToken: async (oldJti, ctx) => {
      await redis.set(`revoked:${oldJti}`, "1", { EX: REFRESH_TTL_SECONDS });
      if (ctx?.familyId) {
        await redis.sAdd(`family:${ctx.familyId}`, oldJti);
      }
    },
    // Register the new token under the family
    registerRefreshToken: async (newJti, ctx) => {
      if (ctx?.familyId) {
        await redis.sAdd(`family:${ctx.familyId}`, newJti);
      }
    },
    // Token reuse detected! Invalidate the whole family
    onRefreshReuse: async (ctx) => {
      if (!ctx.familyId) return;
      const allTokens = await redis.sMembers(`family:${ctx.familyId}`);
      for (const tokenJti of allTokens) {
        await redis.set(`revoked:${tokenJti}`, "1", { EX: REFRESH_TTL_SECONDS });
      }
    },
  },
});
```

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
import { isAuthError, AuthError, AUTH_ERROR_CODES } from "@wtfdrshn/zero-auth";

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
| `AUTH_FORBIDDEN` | `403` | User is authenticated but does not possess the required role. |

---

## TypeScript Support

`zero-auth` automatically augments Express's `Request` type with `req.user`.

```ts
import type { AuthUser } from "@wtfdrshn/zero-auth";

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
| `optional()` | `RequestHandler` | Express middleware: sets `req.user` if valid token present, allows guests. |
| `sendAuthTokens(res, payload)` | `Promise<TokenPair>` | Sets access + refresh HTTP-only cookies on `res` and returns tokens. |
| `clearAuth(res)` | `void` | Clears access and refresh auth cookies from `res`. |
| `refreshHandler()` | `RequestHandler` | Express route handler for refreshing access tokens. |
| `rotateTokens(payload)` | `Promise<TokenPair>` | Generates a new access + refresh pair (for custom rotation logic). |
| `initialize()` | `RequestHandler` | App-level initialization middleware (`app.use(auth.initialize())`). |
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
} from "@wtfdrshn/zero-auth";
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
3. **Token Lifespans**:
   - Keep `accessExpiresIn` short (`15m` recommended).
   - Refresh tokens can have longer lifespans (`7d` - `30d`).
4. **Token Revocation in Distributed Systems**:
   - Use Redis or your primary database with TTLs to track revoked `jti` identifiers when `refreshOptions.rotate: true` is enabled.

---

## Compatibility

| Environment | Supported | Notes |
|---|:---:|---|
| **Node.js** | >= 18.0.0 | Full ESM & CommonJS support |
| **Express** | 4.x & 5.x | Peer dependency for middleware |
| **Bun** | >= 1.0.0 | Native runtime support |
| **TypeScript** | >= 5.0.0 | Declarations bundled |
| **Serverless / Edge** | ✅ | Powered by `jose` (Web Crypto API compliant) |

---

## License

[MIT](./LICENSE) © zero-auth contributors
