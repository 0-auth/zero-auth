# Deployment

This guide covers production settings for applications using `zero-auth`.

## Production checklist

- Set separate, random secrets for access and refresh tokens.
- Never use the development fallback secrets from the example app.
- Use HTTPS in production.
- Set cookie `secure: true` when using HTTP-only cookies.
- Set `NODE_ENV=production`.
- Use a shared refresh-token store when running multiple instances.

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
Use `sameSite: "none"` only when the cross-site flow requires it, together
with `secure: true`.

## Multiple instances

Access-token verification is stateless. Refresh-token rotation is not:
`consumeRefreshToken` needs an atomic operation in a shared store such as Redis
or a database when requests can reach different instances. The legacy
`isRevoked` + `revokeRefreshToken` pair is retained in 1.1.x with a warning but
is not concurrency-safe.

The in-memory revocation store is suitable for local development and single-
process tests, not for horizontally scaled production deployments.
