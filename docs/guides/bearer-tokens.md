# Bearer tokens

Bearer tokens work well for mobile apps, CLIs, server-to-server calls, and
frontends that keep an application-managed session. The client sends the
access token explicitly in the `Authorization` header.

## Create the auth instance

Use separate secrets and keep the access lifetime short:

```ts
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d"
});
```

`zero-auth` does not validate passwords or store users. Validate credentials
with your database, then put only the claims needed by the API in the token.

## Login and protect a route

```ts
app.post("/auth/login", async (req, res, next) => {
  try {
    const user = await users.verifyCredentials(req.body.email, req.body.password);
    if (!user) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const tokens = await auth.generateTokenPair({
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
    });
    res.json(tokens);
  } catch (error) {
    next(error);
  }
});

app.get("/api/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.use(auth.errorHandler);
```

`protect()` verifies the access-token signature and expiration, then attaches
the verified payload to `req.user`. Always mount the error handler after the
routes.

## Call the API

```bash
curl https://api.example.com/api/profile \
  -H "Authorization: Bearer <access-token>"
```

Missing, malformed, expired, or incorrectly signed tokens return a structured
401 response. See the [error reference](/errors).

## Refresh an expired access token

The built-in handler accepts the refresh token from a JSON body, bearer header,
or configured refresh cookie:

```ts
app.post("/auth/refresh", auth.refreshHandler());
```

For a JSON client:

```bash
curl -X POST https://api.example.com/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
```

Replace the stored access token with the returned token. If rotation is
enabled, replace the refresh token too and retry the original request once.
Do not create an infinite automatic retry loop.

## Client storage

Keep access tokens in memory when practical. If a refresh token must survive a
restart, use the platform's secure storage rather than a URL, log, or shared
plain-text file. For browser applications, compare this approach with the
[HTTP-only cookie flow](/guides/cookies).

## What this flow does not provide

Bearer authentication does not automatically provide password hashing, user
lookup, logout invalidation, rate limiting, or token revocation. Add those in
your application when the product requires them.
