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
  refreshOptions: {
    rotate: true,
    consumeRefreshToken: (jti, context) =>
      store.consume(jti, context?.familyId),
    registerRefreshToken: (jti, context) =>
      store.register(jti, context.familyId),
    onRefreshReuse: async (context) => {
      if (context.familyId) await store.revokeFamily(context.familyId);
    },
  },
});
~~~

The in-memory store is useful for tests and one-process development only. Use
the same interface with Redis or a database in production.

## Request lifecycle

1. The handler verifies the refresh JWT signature, expiration, and required
   identity claims.
2. consumeRefreshToken atomically marks the incoming jti as used.
3. If the mark already exists, the request is rejected as a replay.
4. A successful request receives a new access/refresh pair.
5. registerRefreshToken tracks the replacement jti under the token family.
6. onRefreshReuse can revoke every known token in a compromised family.

The stable family ID is available as context.familyId when rotation is
enabled. The user ID is available as context.userId.

## Redis requirements

For multiple application instances, the consume operation must be atomic
across all instances. The included cookie/Redis example uses Redis SET NX:

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

Use a TTL at least as long as the refresh-token lifetime, with enough margin
for clock skew. Store family membership with a matching TTL.

## Replay behavior

The first request with a rotated refresh token returns 200 and a replacement
pair. A concurrent or later request with the old token returns
401 AUTH_TOKEN_INVALID and calls onRefreshReuse when configured.

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
