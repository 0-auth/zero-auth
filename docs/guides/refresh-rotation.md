# Refresh token rotation

The built-in refresh handler accepts a refresh token from a cookie, JSON body,
or bearer header:

```ts
app.post("/auth/refresh", auth.refreshHandler());
```

Enable rotation when you want each refresh token to be single-use:

```ts
const revokedTokens = new Set<string>();
const activeTokens = new Set<string>();

const auth = createAuth({
  accessSecret: process.env.JWT_ACCESS_SECRET!,
  refreshSecret: process.env.JWT_REFRESH_SECRET!,
  refreshOptions: {
    rotate: true,
    isRevoked: async (jti) => revokedTokens.has(jti),
    revokeRefreshToken: async (jti) => {
      revokedTokens.add(jti);
    },
    registerRefreshToken: async (jti) => {
      activeTokens.add(jti);
    },
    onRefreshReuse: async (context) => {
      // Revoke the complete token family in your database or Redis store.
      console.warn("Refresh token reuse detected", context.familyId);
    },
  },
});
```

Use a shared store such as Redis when the application runs on multiple
instances. The in-memory store is useful for local development only.
