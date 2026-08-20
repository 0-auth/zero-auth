# RBAC and optional authentication

## Role-based access control

Always run `protect()` before `authorize()` so the user is available.

```ts
app.get(
  "/admin",
  auth.protect(),
  auth.authorize(["admin"]),
  adminHandler,
);

app.get(
  "/reports",
  auth.protect(),
  auth.authorize(["admin", "manager", "auditor"]),
  reportsHandler,
);
```

`authorize()` checks `req.user.role` and allows a user with any listed role.

## Optional authentication

Use `optional()` when guests and signed-in users can both access an endpoint.

```ts
app.get("/articles/:slug", auth.optional(), (req, res) => {
  res.json({
    article: getArticle(req.params.slug),
    bookmarked: Boolean(req.user),
  });
});
```
