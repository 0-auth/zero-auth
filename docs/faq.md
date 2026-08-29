# FAQ and troubleshooting

## Why does `createAuth()` reject my secret?

Access and refresh secrets must each be at least 32 characters. Use separate
values and load them from environment variables:

```ts
const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
});
```

Do not use short demo strings in production.

## Why is every request `AUTH_TOKEN_MISSING`?

For bearer authentication, send the access token—not the refresh token—in the
header:

```http
Authorization: Bearer eyJ...
```

For cookies, confirm that the browser is storing the cookie and that the client
request includes credentials:

```ts
fetch("https://api.example.com/profile", {
  credentials: "include",
});
```

## Why are cookies not being set?

Check these values:

- The response is from the same expected domain.
- `secure: true` is used only when the request is HTTPS.
- `sameSite` matches your frontend/API deployment layout.
- The cookie `domain` and `path` include the endpoint that needs the cookie.
- Cross-origin requests send credentials and the server allows credentials in CORS.

During local HTTP development, use `secure: false` explicitly if your cookie
configuration does not already choose that automatically.

## Why does the browser block my cross-origin request?

Configure CORS in the API and include credentials in browser requests when
using cookies. Do not use `Access-Control-Allow-Origin: *` with credentials.

```ts
import cors from "cors";

app.use(
  cors({
    origin: "https://app.example.com",
    credentials: true,
  }),
);
```

Bearer-token clients usually send the token header and do not need cookie
credentials.

## Why do secure cookies fail behind a proxy?

If HTTPS terminates at a load balancer, configure Express to trust the proxy
hops you control:

```ts
app.set("trust proxy", 1);
```

Also verify that the proxy forwards the original protocol and that your public
URL is HTTPS.

## Why is `AUTH_TOKEN_INVALID` returned after refresh?

Check whether refresh rotation is enabled. With rotation, the old refresh token
is intentionally invalid after it has been used once. Reusing it can trigger
`onRefreshReuse` and revoke its token family.

Other common causes:

- The refresh token was signed with the wrong `refreshSecret`.
- The access token was sent to the refresh endpoint.
- The token was truncated or copied with surrounding quotes.
- A revocation callback reports the token as revoked.

## Why does TypeScript say `req.user` does not exist?

Import the package in the application and ensure the project includes the
package declarations. `req.user` is available after the package's Express type
augmentation is loaded:

```ts
import { createAuth } from "@0-auth/zero-auth";
```

Use `auth.protect()` before accessing `req.user`; it may be undefined on routes
using `auth.optional()`.

## Can I use the in-memory revocation store in production?

Only for a single process with no restart or scaling requirements. Use Redis or
a database for multiple instances, deployments that restart, and refresh-token
reuse detection.

## Why does a permission check return AUTH_FORBIDDEN?

Run protect() before authorizePermissions() and make sure the verified JWT
contains every required string in its permissions claim:

~~~ts
app.get(
  "/reports",
  auth.protect(),
  auth.authorizePermissions(["reports:read", "reports:export"]),
  handler,
);
~~~

Permission checks require all listed permissions. They do not replace
application checks for tenant or record ownership.

## Why do cookie writes return AUTH_CSRF_INVALID?

Call the CSRF endpoint with credentials, keep the returned CSRF cookie, and
copy the returned token into the configured request header. Check that the
request still includes credentials and that cookie path, domain, and SameSite
settings match the deployment.

## Why does refresh fail under load?

Rotated refresh tokens are single-use. Concurrent requests using the same
refresh token should produce one success and rejected replays. Use
consumeRefreshToken with an atomic shared-store operation; the legacy split
hooks are not concurrency-safe.

## What should I log?

Log the error code, status, route, and request ID. Never log access tokens,
refresh tokens, signing secrets, or complete cookie values.
