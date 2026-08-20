# HTTP-only cookies

Cookies are convenient for browser applications because JavaScript cannot read
an HTTP-only cookie.

```ts
app.post("/auth/login", async (req, res, next) => {
  try {
    // Validate credentials before creating tokens.
    const user = { id: "user-123", role: "member" };
    await auth.sendAuthTokens(res, user);
    res.json({ user });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});

app.post("/auth/logout", (req, res) => {
  auth.clearAuth(res);
  res.json({ message: "Logged out" });
});
```

For production, use HTTPS so secure cookies are protected in transit. Configure
cookie names and `sameSite` under [configuration](/configuration#cookies).
