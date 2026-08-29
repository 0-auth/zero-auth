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

## Permission-based access control

Use `authorizePermissions()` for fine-grained checks. The user must have every
listed permission in the JWT `permissions` claim.

```ts
app.get(
  "/users",
  auth.protect(),
  auth.authorizePermissions(["users:read"]),
  listUsersHandler,
);
```

It returns `AUTH_FORBIDDEN` when a required permission is missing.

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
