# Express Cookie Auth + Redis Rotation Example

HTTP-only cookie authentication with refresh token rotation backed by Redis.
When a rotated refresh token is replayed (e.g. stolen), the entire token family
is revoked — forcing re-login.

## Prerequisites

- **Docker** (for Redis) or a Redis instance running on `localhost:6379`
- **Node.js 18+**

## Setup

```bash
# 1. Start Redis
cd examples/express-cookies-redis
docker compose up -d

# 2. Create .env from template
cp .env.example .env

# 3. Install dependencies
npm install

# 4. Start the server
npm start
```

Server starts on **http://localhost:3001**.

## Deploy with Docker Compose

This repository includes a production-mode container for the example. It uses
the root package as a local dependency, so run Compose from this directory:

```bash
cd examples/express-cookies-redis
cp .env.example .env
# Replace both JWT secrets in .env with random values before deploying.
docker compose --profile container up --build -d
```

Check the deployment:

```bash
curl http://localhost:3001/healthz
# {"status":"ok","redis":"ok"}

docker compose logs -f app
```

The `app` container waits for Redis to pass its health check, listens on port
`3001`, uses secure cookies because `NODE_ENV=production`, and shuts down
cleanly on `SIGTERM`. Stop it with:

```bash
docker compose --profile container down
```

To deploy on a Node host instead, provide `NODE_ENV=production`,
`JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `REDIS_URL`, and `PORT` through the
platform's secret/environment settings, then run:

```bash
npm ci --omit=dev
npm start
```

Configure the platform health check as `GET /healthz`. Do not expose Redis to
the public internet; use the private Redis URL supplied by your platform.

## What makes the rotation safe

The refresh flow is deliberately split into clear steps:

1. `zero-auth` verifies the refresh JWT signature, expiry, and `id` claim.
2. `consumeRefreshToken` runs Redis `SET NX` on `revoked:<jti>`. Exactly one
   concurrent request can consume a refresh token.
3. A successful request receives a new access/refresh pair. The new refresh
   `jti` is registered under the token family.
4. A replay returns `401` and calls `onRefreshReuse`, which revokes every known
   `jti` in that family.

The old `isRevoked` + `revokeRefreshToken` callbacks remain supported by
`zero-auth` 1.1.x, but they log a warning and are not safe for concurrent
requests. Use the atomic callback shown in `src/server.ts`.

## Production boundary

This is a deployable authentication reference, not a complete user service.
The example hashes passwords with Node's built-in `scrypt`, never accepts a
client-supplied admin role, and keeps users in memory so the example stays
small. Replace the `users` array with your database before production; user
registrations disappear when the process restarts or a container is replaced.

The example includes CSRF protection for cookie-authenticated writes. For a
real browser application, also add login/refresh rate limits, an allow-listed
CORS policy, HTTPS, and a trusted reverse-proxy configuration.

## Seed Users

| Email                | Password   | Role  |
| -------------------- | ---------- | ----- |
| admin@example.com    | admin123   | admin |
| user@example.com     | user123    | user  |

---

## API Walkthrough

### 1. Login (sets cookies)

```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

Check `cookies.txt` — you'll see `access_token` and `refresh_token` cookies.

### 2. Get a CSRF Token

The endpoint sets a client-readable `csrf_token` cookie and returns the same
signed token. Keep the auth cookies HTTP-only; send this token in the
`x-csrf-token` header for state-changing requests.

```bash
curl http://localhost:3001/auth/csrf-token \
  -b cookies.txt -c cookies.txt
```

Copy the `csrfToken` value from the response for the next commands.

### 3. Access Protected Route (via cookies)

```bash
curl http://localhost:3001/profile -b cookies.txt
```

**Response** `200`:
```json
{
  "user": { "id": "1", "email": "admin@example.com", "role": "admin", ... }
}
```

### 4. Refresh Token (rotation)

```bash
curl -X POST http://localhost:3001/auth/refresh \
  -H "x-csrf-token: <csrfToken>" \
  -b cookies.txt -c cookies.txt
```

This rotates the refresh token — the old one is revoked in Redis and new
cookies are set. Check `cookies.txt` to see the updated values.

### 5. Replay the Old Refresh Token (reuse detection)

If you saved the old `cookies.txt` before step 3 and replay it:

```bash
curl -X POST http://localhost:3001/auth/refresh \
  -H "x-csrf-token: <csrfToken>" \
  -b old-cookies.txt -c old-cookies.txt
```

**Result**: `401` — the server detects reuse, logs a warning, and revokes the
**entire token family**. Even the new refresh token from step 3 is now invalid.

### 6. Logout (clears cookies)

```bash
curl -X POST http://localhost:3001/auth/logout \
  -H "x-csrf-token: <csrfToken>" \
  -b cookies.txt -c cookies.txt
```

**Response** `200`:
```json
{ "message": "Logged out" }
```

### 7. Optional Auth

```bash
# As guest
curl http://localhost:3001/posts

# As authenticated user
curl http://localhost:3001/posts -b cookies.txt
```

### 8. Admin-Only: Delete User

```bash
curl -X DELETE http://localhost:3001/admin/users/2 \
  -H "x-csrf-token: <csrfToken>" \
  -b cookies.txt
```

---

## Architecture

```
┌──────────┐    cookies     ┌──────────────┐    revoke/check    ┌─────────┐
│  Client  │ ◄────────────► │  Express +   │ ◄────────────────► │  Redis  │
│ (browser)│                │  zero-auth   │                    │         │
└──────────┘                └──────────────┘                    └─────────┘
                                   │
                            ┌──────┴──────┐
                            │  store.ts   │
                            │  Redis ops  │
                            └─────────────┘
```

## Features Demonstrated

| Feature                      | Where                                          |
| ---------------------------- | ---------------------------------------------- |
| `createAuth()` + cookies     | Auth initialization with cookie config          |
| `sendAuthTokens(res, user)`  | Register & Login (sets HTTP-only cookies)        |
| `clearAuth(res)`             | Logout (clears cookies)                         |
| `csrf()` + `csrfToken(res)`  | CSRF protection for cookie-authenticated writes |
| `refreshHandler()` + rotate  | `POST /auth/refresh` (rotation + new cookies)   |
| `consumeRefreshToken` hook   | Atomic Redis single-use check before issuing pair |
| `registerRefreshToken` hook  | Tracks new jti under family in Redis            |
| `onRefreshReuse` hook        | Revokes entire family on replay detection        |
| `protect()`                  | `GET /profile`, `DELETE /admin/users/:id`       |
| `authorize(["admin"])`       | `DELETE /admin/users/:id`                       |
| `optional()`                 | `GET /posts`                                    |
| `errorHandler`               | Mounted at app level                            |
| `GET /healthz`               | Redis-backed health check                       |

## Stopping

```bash
# Stop the server (Ctrl+C)
# Stop Redis
docker compose down
```
