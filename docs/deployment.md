# Deployment

This guide covers production settings for applications using `zero-auth`.

## Production checklist

zero-auth does not provision a database, Redis, TLS certificate, process
manager, or user store. Those remain deployment and application decisions.

- Set separate, random secrets for access and refresh tokens.
- Never use the development fallback secrets from the example app.
- Use HTTPS in production.
- Set cookie `secure: true` when using HTTP-only cookies.
- Set `NODE_ENV=production`.
- Use a shared refresh-token store when running multiple instances.
- Mount <code>auth.csrf()</code> for cookie-authenticated state-changing requests.
- Allow only trusted CORS origins when browsers call the API cross-origin.
- Rate-limit login, registration, refresh, and password-reset endpoints.
- Do not log tokens, secrets, or complete cookie headers.
- Add a health check that verifies dependencies required by the app.

## Environment variables

Keep secrets outside the repository:

```bash
NODE_ENV=production
JWT_ACCESS_SECRET=<random-access-secret-at-least-32-characters>
JWT_REFRESH_SECRET=<different-random-refresh-secret-at-least-32-characters>
```

Read them when creating the auth instance:

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
});
```

Your platform should provide these values through its secret manager or
protected environment settings.

Generate values with Node.js:

~~~bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
~~~

Never use the same secret for access and refresh tokens. Changing either
secret invalidates tokens signed with the old value, so plan a coordinated
sign-in or key-migration strategy.

## Express behind a reverse proxy

If TLS terminates at a reverse proxy or load balancer, configure Express to
trust only the proxy hops that you control:

```ts
app.set("trust proxy", 1);
```

## HTTP-only cookies

Use secure cookie settings in production:

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  cookies: {
    options: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    },
  },
});
```

For a browser frontend on another origin, configure CORS and send credentials.
Mount CSRF protection before state-changing routes:

~~~ts
app.use(auth.csrf());

app.get("/auth/csrf-token", (_req, res) => {
  res.json({ csrfToken: auth.csrfToken(res) });
});
~~~

The browser must request the token with credentials and send it in the
configured header on POST, PUT, PATCH, and DELETE requests.

Use `sameSite: "none"` only when the cross-site flow requires it, together
with `secure: true`.

## Multiple instances

Access-token verification is stateless. Refresh-token rotation is not:
`consumeRefreshToken` needs an atomic operation in a shared store such as Redis
or a database when requests can reach different instances. The legacy
`isRevoked` + `revokeRefreshToken` pair remains supported with a warning but is
not concurrency-safe. The built-in Redis adapter also marks a compromised
family before registering replacements, closing the replay/revocation race.

The in-memory revocation store is suitable for local development and single-
process tests, not for horizontally scaled production deployments.

## Health checks and shutdown

Expose a health endpoint that checks the dependencies required to serve
requests. The cookie/Redis example uses <code>GET /healthz</code> and returns
503 when Redis is unavailable. Keep liveness and readiness separate if your
platform supports both.

On <code>SIGTERM</code>, stop accepting new traffic, finish in-flight requests,
close the Redis connection, and then exit. Configure the platform's
graceful-shutdown timeout to exceed the expected request duration.

## Deployment sequence

1. Store secrets and production configuration in the platform secret manager.
2. Run database migrations and verify the refresh-token store is reachable.
3. Deploy the API with HTTPS and the correct proxy trust configuration.
4. Verify health, login, protected routes, refresh, CSRF, and logout.
5. Roll out gradually while monitoring authentication failures and refresh
   reuse events.
6. Confirm the previous deployment can be rolled back without losing required
   revocation state.

For a complete Docker and Redis reference, use the
[cookie + Redis example](https://github.com/0-auth/zero-auth/tree/master/examples/express-cookies-redis).
