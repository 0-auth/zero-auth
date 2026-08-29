# Runnable REST API example

This example demonstrates bearer-token authentication with Express, including
login, protected routes, refresh, optional authentication, and RBAC.

It is intentionally stateless: refresh requests do not use a revocation store.
Use the cookie + Redis example when you need cookie sessions and replay
detection.

## Start it

```bash
cd examples/express-rest-api
npm install
npm start
```

The server runs at `http://localhost:3000` and includes these demo users:

| Email | Password | Role |
| --- | --- | --- |
| `admin@example.com` | `admin123` | `admin` |
| `user@example.com` | `user123` | `user` |

The example uses an in-memory user list and plain-text demo passwords. Do not
copy that storage or password handling into production.

The example has development fallback secrets. In a real app, set secrets in
the environment instead:

```bash
JWT_ACCESS_SECRET="replace-with-a-long-access-secret"
JWT_REFRESH_SECRET="replace-with-a-different-long-refresh-secret"
```

## Log in

```bash
login=$(curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}')

echo "$login"
```

The response contains an `accessToken` and a `refreshToken`:

```json
{
  "user": { "id": "1", "email": "admin@example.com", "role": "admin" },
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

Copy the two token values into shell variables:

```bash
accessToken="<access-token-from-login>"
refreshToken="<refresh-token-from-login>"
```

## Call a protected route

```bash
curl http://localhost:3000/profile \
  -H "Authorization: Bearer $accessToken"
```

Without the header, the same route returns `401 AUTH_TOKEN_MISSING`.

## Refresh the access token

```bash
curl -s -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"'"$refreshToken"'"}'
```

## Try optional auth and RBAC

Guests see only public posts:

```bash
curl http://localhost:3000/posts
```

Authenticated users see their personalized response:

```bash
curl http://localhost:3000/posts \
  -H "Authorization: Bearer $accessToken"
```

The admin token can delete a user:

```bash
curl -X DELETE http://localhost:3000/admin/users/2 \
  -H "Authorization: Bearer $accessToken"
```

A token belonging to the regular user receives `403 AUTH_FORBIDDEN` for that
route.

## Run the automated example test

~~~bash
npm test
~~~

The test starts the app on an ephemeral port and checks registration, login,
protected access, missing-token behavior, optional authentication, refresh,
RBAC, and token inspection.

The route uses role authorization. For fine-grained application policies, use
the package permission claim and middleware:

~~~ts
app.get(
  "/reports",
  auth.protect(),
  auth.authorizePermissions(["reports:read"]),
  reportsHandler,
);
~~~

See the [access-control guide](/guides/access-control) for role, permission,
and ownership checks.

See the complete source and additional endpoints in
[`examples/express-rest-api`](https://github.com/0-auth/zero-auth/tree/master/examples/express-rest-api).
