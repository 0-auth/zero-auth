# Runnable REST API example

This example demonstrates bearer-token authentication with Express, including
login, protected routes, refresh, optional authentication, and RBAC.

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

See the complete source and additional endpoints in
[`examples/express-rest-api`](https://github.com/0-auth/zero-auth/tree/main/examples/express-rest-api).
