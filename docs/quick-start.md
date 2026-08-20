# Quick start

## 1. Install

```bash
npm install @0-auth/zero-auth express
```

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

Next: choose [Bearer tokens](/guides/bearer-tokens) or [HTTP-only cookies](/guides/cookies).
