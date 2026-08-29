# Access control and optional authentication

Authentication establishes who the caller is. Authorization decides what that
caller may do. Always authenticate with `protect()` before applying role or
permission middleware.

## Role-based access control

`authorize()` allows a user whose single `req.user.role` matches any role in
the allow-list:

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

Use roles for broad application areas. A missing role or a non-matching role
returns `403 AUTH_FORBIDDEN`.

## Permission-based access control

Use `authorizePermissions()` for fine-grained checks. The user must have every
listed permission in the JWT `permissions` claim:

```ts
app.patch(
  "/users/:id",
  auth.protect(),
  auth.authorizePermissions(["users:read", "users:update"]),
  updateUserHandler,
);
```

Recommended permission names are explicit and resource-oriented:

```text
users:read
users:create
users:update
users:delete
reports:export
```

Use separate middleware calls when a route has separate authorization rules.
Permission checks do not replace resource ownership checks; the handler must
still verify that the user may access the specific record.

## Combining roles and permissions

Use both checks when a route needs a broad role and a specific capability:

```ts
app.delete(
  "/users/:id",
  auth.protect(),
  auth.authorize(["admin", "support"]),
  auth.authorizePermissions(["users:delete"]),
  deleteUserHandler,
);
```

Middleware runs from left to right. If `req.user` is missing because
`protect()` was omitted or mounted later, the authorization middleware returns
`401 AUTH_UNAUTHORIZED`.

## Optional authentication

Use `optional()` when guests and signed-in users can both access an endpoint:

```ts
app.get("/articles/:slug", auth.optional(), (req, res) => {
  res.json({
    article: getArticle(req.params.slug),
    bookmarked: Boolean(req.user),
  });
});
```

`optional()` never rejects a request. It sets `req.user` when a valid token is
present and leaves it undefined for guests or invalid tokens.

## Testing authorization

Test at least these paths:

- No token: `401 AUTH_TOKEN_MISSING` from `protect()`.
- No `req.user`: `401 AUTH_UNAUTHORIZED` from authorization middleware.
- Wrong role or missing permission: `403 AUTH_FORBIDDEN`.
- Matching role or all required permissions: handler executes.
- Authenticated user with a forbidden resource ID: handler still rejects it.
