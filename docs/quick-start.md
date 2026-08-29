# Quick start

## 1. Install

```bash
npm install @0-auth/zero-auth express
```

`zero-auth` supports Node.js 18+ and Express 4 or 5. This guide uses bearer
tokens; use the [cookie guide](/guides/cookies) for browser sessions.

## 2. Create the auth instance

Secrets must be at least 32 characters long. Keep access and refresh secrets
different.

```ts
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  accessExpiresIn: "15m",
  refreshExpiresIn: "7d",
});
```

Use separate high-entropy secrets. For local development only:

```bash
export JWT_ACCESS_SECRET="replace-with-a-random-access-secret-at-least-32-characters"
export JWT_REFRESH_SECRET="replace-with-a-different-refresh-secret-at-least-32-characters"
```

## 3. Protect routes

```ts
import express from "express";

const app = express();
app.use(express.json());

app.post("/auth/login", async (req, res, next) => {
  try {
    // Replace this with your database credential check.
    const user = { id: "user-123", email: req.body.email, role: "user" };
    const tokens = await auth.generateTokenPair(user);
    res.json(tokens);
  } catch (error) {
    next(error);
  }
});

app.get("/api/profile", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.post("/auth/refresh", auth.refreshHandler());
app.use(auth.errorHandler);

app.listen(3000);
```

The client sends the access token on protected requests:

```http
Authorization: Bearer <access-token>
```

Check the route with cURL:

```bash
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer <access-token>"
```

Without a token, the error handler returns `401 AUTH_TOKEN_MISSING`. An
authenticated user who fails a role or permission check receives
`403 AUTH_FORBIDDEN`.

Next: choose [Bearer tokens](/guides/bearer-tokens),
[HTTP-only cookies](/guides/cookies), or review the
[configuration reference](/configuration).
