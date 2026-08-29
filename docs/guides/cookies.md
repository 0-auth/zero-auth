# HTTP-only cookies

Cookies are convenient for browser applications because JavaScript cannot read
HTTP-only token cookies. The browser sends them automatically, so every
state-changing cookie request also needs CSRF protection.

## Configure cookies

```ts
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  cookies: {
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    },
  },
});
```

Use `secure: true` over HTTPS in production. Match the cookie path and domain
to the routes that need the cookies.

## Login, protect, refresh, and logout

```ts
app.post("/auth/login", async (req, res, next) => {
  try {
    const user = await users.verifyCredentials(req.body.email, req.body.password);
    if (!user) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    await auth.sendAuthTokens(res, {
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
    });
    res.json({ user: { id: user.id, email: user.email } });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.post("/auth/refresh", auth.refreshHandler());

app.post("/auth/logout", (_req, res) => {
  auth.clearAuth(res);
  res.json({ message: "Logged out" });
});
```

`sendAuthTokens()` sets HTTP-only access and refresh cookies. `clearAuth()`
clears them using the configured cookie attributes.

## CSRF protection

Mount the middleware before state-changing routes:

```ts
app.use(auth.csrf());

app.get("/auth/csrf-token", (_req, res) => {
  res.json({ csrfToken: auth.csrfToken(res) });
});
```

The browser first obtains the token, stores the readable `csrf_token` cookie,
and copies the returned value into the configured `x-csrf-token` header:

```ts
const csrfResponse = await fetch("/auth/csrf-token", {
  credentials: "include",
});
const { csrfToken } = await csrfResponse.json();

await fetch("/api/account", {
  method: "POST",
  credentials: "include",
  headers: { "x-csrf-token": csrfToken },
});
```

By default, `POST`, `PUT`, `PATCH`, and `DELETE` are checked when an
access or refresh auth cookie is present. `GET`, `HEAD`, and unauthenticated
requests pass through. A missing, mismatched, tampered, or malformed token
returns `403 AUTH_CSRF_INVALID`.

Customize the cookie name, header name, or methods with
[`CsrfConfig`](/api/interfaces/CsrfConfig.html).

## Cross-origin browsers

For a frontend on another origin, configure an allow-listed CORS policy and
send credentials. Do not combine credentials with
`Access-Control-Allow-Origin: *`. Use `sameSite: "none"` only when the
deployment truly requires a cross-site cookie and always pair it with HTTPS
and `secure: true`.

See the [security checklist](/security) before deploying cookie sessions.
