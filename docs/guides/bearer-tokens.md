# Bearer tokens

Bearer tokens work well for mobile apps, CLIs, and APIs used by separate
frontends.

```ts
app.post("/auth/login", async (req, res) => {
  // Validate credentials before creating tokens.
  const tokens = await auth.generateTokenPair({
    id: "user-123",
    email: "user@example.com",
    role: "user",
  });

  res.json(tokens);
});

app.get("/api/data", auth.protect(), (req, res) => {
  res.json({ user: req.user, data: "protected content" });
});
```

Send the access token with each request:

```bash
curl http://localhost:3000/api/data \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Use the refresh endpoint when the access token expires:

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"'"$REFRESH_TOKEN"'"}'
```
