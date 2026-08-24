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
    consumeRefreshToken: async (jti) => {
      if (revokedTokens.has(jti)) return false;
      revokedTokens.add(jti);
      return true;
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
instances. The in-memory store is useful for local development only. The
legacy `isRevoked` + `revokeRefreshToken` hooks remain supported in 1.1.x with
a warning, but use the atomic hook for concurrent or distributed traffic.
