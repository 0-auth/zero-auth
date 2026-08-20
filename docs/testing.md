# Testing

The repository uses [Vitest](https://vitest.dev/) for tests and
[Supertest](https://github.com/ladjs/supertest) for Express integration tests.

## Run the test suite

```bash
npm test
```

Useful commands:

```bash
npm run test:watch       # rerun tests while editing
npm run test:coverage    # generate coverage reports
npm run typecheck        # validate TypeScript without emitting files
```

## Test a protected route

Keep the app in memory and call it with Supertest. Do not start a network
listener in the test file.

```ts
import express from "express";
import request from "supertest";
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  accessSecret: "test-access-secret-at-least-32-characters",
  refreshSecret: "test-refresh-secret-at-least-32-characters",
});

const app = express();
app.get("/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});
app.use(auth.errorHandler);

it("rejects a request without a token", async () => {
  const response = await request(app).get("/profile");

  expect(response.status).toBe(401);
  expect(response.body.error.code).toBe("AUTH_TOKEN_MISSING");
});

it("accepts a valid access token", async () => {
  const { accessToken } = await auth.generateTokenPair({
    id: "user-1",
    role: "user",
  });

  const response = await request(app)
    .get("/profile")
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toBe(200);
  expect(response.body.user.id).toBe("user-1");
});
```

## Test roles

Test both sides of an authorization boundary:

```ts
app.get(
  "/admin",
  auth.protect(),
  auth.authorize(["admin"]),
  (_req, res) => res.json({ ok: true }),
);

const { accessToken } = await auth.generateTokenPair({
  id: "user-1",
  role: "user",
});

const response = await request(app)
  .get("/admin")
  .set("Authorization", `Bearer ${accessToken}`);

expect(response.status).toBe(403);
expect(response.body.error.code).toBe("AUTH_FORBIDDEN");
```

## Test expiry and refresh

Use a short-lived token or sign a token with an expiration in the past, then
assert the exact error code:

```ts
await expect(auth.verifyToken(expiredToken)).rejects.toMatchObject({
  code: "AUTH_TOKEN_EXPIRED",
  statusCode: 401,
});
```

For refresh rotation, test both the first refresh and replay of the old refresh
token. The replay should return `AUTH_TOKEN_INVALID` and call your
`onRefreshReuse` callback.

## What to test in an application

- Missing, malformed, expired, and tampered tokens
- Access tokens rejected where refresh tokens are expected
- Users with allowed and disallowed roles
- Cookie flags and logout behavior
- Refresh-token replay and family revocation
- Error responses without leaking secrets or raw token contents
