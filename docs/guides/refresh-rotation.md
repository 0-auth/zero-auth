# Refresh token rotation

Refresh tokens keep a session alive after a short-lived access token expires.
Rotation makes each refresh token single-use, which limits the value of a
stolen token and makes replay detectable.

## Basic refresh handler

The built-in handler accepts a refresh token from a configured cookie, JSON
body, or Authorization: Bearer header:

~~~ts
app.post("/auth/refresh", auth.refreshHandler());
~~~

With rotation disabled, the handler issues a new access token and keeps the
refresh token unchanged:

~~~bash
curl -X POST https://api.example.com/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
~~~

This mode is stateless, but it does not detect refresh-token replay.

## Enable rotation

Rotation requires an atomic consume operation. The operation must return true
only when it marks the incoming jti for the first time:

~~~ts
import {
  createAuth,
  createInMemoryRevocationStore,
} from "@0-auth/zero-auth";

const store = createInMemoryRevocationStore();

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  refreshStore: store,
  refreshOptions: {
    rotate: true,
  },
});
~~~

`RefreshTokenStore` supplies atomic consumption, replacement registration, and
family revocation automatically. Its `consume()` method is required;
`register()` and `revokeFamily()` are optional. The in-memory store is useful
for tests and one-process development only; use Redis or a database in
production.

## Request lifecycle

1. The handler verifies the refresh JWT signature, expiration, and required
   identity claims.
2. refreshStore.consume atomically marks the incoming jti as used.
3. If the mark already exists, the request is rejected as a replay.
4. A successful request receives a new access/refresh pair.
5. refreshStore.register tracks the replacement jti under the token family.
6. refreshStore.revokeFamily can revoke every known token in a compromised family.

The stable family ID is available as context.familyId when rotation is
enabled. The user ID is available as context.userId.

## Redis requirements

For multiple application instances, `refreshStore.consume()` must be atomic
across all instances. The package includes an adapter for ioredis-compatible
clients:

~~~ts
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
  refreshOptions: { rotate: true },
});
~~~

The adapter uses Redis `SET NX` internally:

~~~ts
const result = await redis.set(
  "revoked:" + jti,
  "1",
  "EX",
  REFRESH_TTL_SECONDS,
  "NX",
);
return result === "OK";
~~~

The package does not install a Redis client. Add `ioredis` to the application,
and pass its client instance to `createRedisRevocationStore()`.

Use a TTL at least as long as the refresh-token lifetime, with enough margin
for clock skew. Store family membership with a matching TTL.

When `revokeFamily()` runs, the Redis adapter marks the family compromised
before scanning its members. `register()` checks that marker atomically, so a
replacement that races with replay handling is rejected instead of returned as
usable.

## Replay behavior

The first request with a rotated refresh token returns 200 and a replacement
pair. A concurrent or later request with the old token returns
401 AUTH_TOKEN_INVALID and calls onRefreshReuse when configured.

During a true concurrent replay, family revocation can win before the first
request registers its replacement. In that case both requests fail closed with
401; no new usable refresh token is returned.

If the application revokes the token family after reuse, the legitimate
replacement token also becomes invalid and the user must sign in again.

## Legacy hooks

isRevoked plus revokeRefreshToken remain supported for compatibility, but they
perform a check followed by a separate write and therefore are not safe against
concurrent requests. They emit a warning. Migrate to consumeRefreshToken for
rotated sessions, especially in distributed deployments.

## Failure behavior

If the consume or registration store fails, the refresh request fails closed
with 401 AUTH_TOKEN_INVALID. Do not return newly issued tokens when the
application cannot record their rotation state.

For a complete Redis-backed deployment, see the
[cookie + Redis example](https://github.com/0-auth/zero-auth/tree/master/examples/express-cookies-redis).
