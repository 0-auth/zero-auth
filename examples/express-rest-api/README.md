# Express REST API Example

Stateless Bearer-token authentication for mobile apps, CLI tools, and SPAs.

## Setup

```bash
cd examples/express-rest-api
npm install
npm start
```

Server starts on **http://localhost:3000**.

This example is a stateless bearer-token reference. It keeps users in memory
and uses demo password handling, so replace both with a database and a real
password-hashing policy before production. Use the cookie + Redis example for
HTTP-only cookies, CSRF protection, and refresh-token replay detection.

## Seed Users

| Email                | Password   | Role  |
| -------------------- | ---------- | ----- |
| admin@example.com    | admin123   | admin |
| user@example.com     | user123    | user  |

---

## API Endpoints

### Register

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"new@example.com","password":"pass123","role":"user"}'
```

**Response** `201`:
```json
{
  "user": { "id": "3", "email": "new@example.com", "role": "user" },
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

**Response** `200`:
```json
{
  "user": { "id": "1", "email": "admin@example.com", "role": "admin" },
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

### Access Protected Route

```bash
# Replace <accessToken> with the token from login
curl http://localhost:3000/profile \
  -H "Authorization: Bearer <accessToken>"
```

**Response** `200`:
```json
{
  "user": { "id": "1", "email": "admin@example.com", "role": "admin", "iat": 1234567890, "exp": 1234568790, "jti": "..." }
}
```

**Without token** → `401`:
```json
{ "error": { "code": "AUTH_TOKEN_MISSING", "message": "Authentication token is missing.", "statusCode": 401 } }
```

### Optional Auth (Guest vs Authenticated)

```bash
# As guest (no token)
curl http://localhost:3000/posts

# As authenticated user
curl http://localhost:3000/posts \
  -H "Authorization: Bearer <accessToken>"
```

### Refresh Token

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'
```

**Response** `200`:
```json
{ "accessToken": "eyJ..." }
```

### Admin-Only: Delete User

```bash
# Must be logged in as admin
curl -X DELETE http://localhost:3000/admin/users/2 \
  -H "Authorization: Bearer <adminAccessToken>"
```

**Response** `200`:
```json
{ "message": "User 2 deleted", "deletedBy": "1" }
```

**As non-admin** → `403`:
```json
{ "error": { "code": "AUTH_FORBIDDEN", "message": "Forbidden. You do not have permission to access this resource.", "statusCode": 403 } }
```

### Token Introspection (Debug)

```bash
curl "http://localhost:3000/token/inspect?token=<anyJwt>"
```

Returns the decoded payload without verifying the signature — useful for debugging.

---

## Run the automated example test

~~~bash
npm test
~~~

The test starts the app on an ephemeral port and checks registration, login,
protected access, missing-token behavior, optional authentication, refresh,
RBAC, and token inspection.

## Features Demonstrated

| Feature                    | Where                                    |
| -------------------------- | ---------------------------------------- |
| `createAuth()`             | Auth initialization                      |
| `generateTokenPair()`      | Register & Login                         |
| `protect()`                | `GET /profile`, `DELETE /admin/users/:id` |
| `authorize(["admin"])`     | `DELETE /admin/users/:id`                |
| `optional()`               | `GET /posts`                             |
| `refreshHandler()`         | `POST /auth/refresh`                     |
| `decodeToken()`            | `GET /token/inspect`                     |
| `errorHandler`             | Mounted at app level                     |
