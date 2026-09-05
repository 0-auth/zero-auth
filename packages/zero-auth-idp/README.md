# @0-auth/zero-auth-idp

> [!NOTE]
> This is an OAuth 2.0 authorization server, not an OpenID Connect provider.
> Version `0.1.0` intentionally has no ID tokens, user registration, refresh
> tokens, social login, or admin dashboard.

A small, self-hosted OAuth authorization server for Express applications. It
provides a backend-hosted login and consent UI, Authorization Code + PKCE, and
opaque access tokens without requiring a second server.

## Install

```bash
npm install @0-auth/zero-auth-idp express
```

## Quick start

The application owns users and verifies credentials. The package owns the
OAuth flow and receives a small user object after successful authentication.

```ts
import express from "express";
import { createIdentityProvider } from "@0-auth/zero-auth-idp";

const idp = createIdentityProvider({
  issuer: "http://localhost:3000/auth",
  clients: [
    {
      clientId: "demo-app",
      name: "Demo app",
      clientType: "public",
      redirectUris: ["http://localhost:4000/callback"],
      allowedScopes: ["profile", "projects:read"],
    },
  ],
  authenticateUser: async ({ email, password }) => {
    // Replace this with your application's user lookup and password check.
    if (email !== "user@example.com" || password !== "change-me") return null;
    return { id: "user-123", email };
  },
});

const app = express();
app.use("/auth", idp.router());

app.get("/api/projects", idp.authenticateBearer(["projects:read"]), (req, res) => {
  res.json({ userId: req.idpUser?.id, projects: [] });
});

app.listen(3000);
```

The hosted flow is:

```text
/authorize -> /login -> /consent -> client callback
                         |
                         +-> /token (code + PKCE verifier)
```

The client must use `response_type=code`, `code_challenge_method=S256`, and a
registered redirect URI. The authorization code is short-lived and single-use.

For a runnable application and curl walkthrough, see
[`examples/express-idp`](../../examples/express-idp).

## Endpoints

When mounted at `/auth`:

| Endpoint                                           | Purpose                                    |
| -------------------------------------------------- | ------------------------------------------ |
| `GET /auth/.well-known/oauth-authorization-server` | OAuth metadata                             |
| `GET /auth/authorize`                              | Start Authorization Code + PKCE            |
| `GET/POST /auth/login`                             | Hosted login UI                            |
| `GET/POST /auth/consent`                           | Hosted consent UI                          |
| `POST /auth/token`                                 | Exchange a code for an access token        |
| `POST /auth/introspect`                            | Inspect a token with a confidential client |
| `POST /auth/revoke`                                | Revoke an access token                     |
| `POST /auth/logout`                                | End the browser session                    |

Access tokens are opaque, short-lived Bearer tokens. Use the returned token
with `Authorization: Bearer <token>` and protect resource routes with
`idp.authenticateBearer()`.

## Storage

The default in-memory storage is useful for local development and tests. It is
not durable and must not be used for a multi-instance deployment.

Implement `OAuthStorage` for a database or shared cache, then pass it as
`storage`. The adapter must store hashes for session, authorization-code, and
access-token values, and `consumeAuthorizationCode` must be atomic.

## Security defaults

- PKCE with `S256` is mandatory.
- Redirect URIs must match exactly and cannot contain fragments.
- Authorization codes are short-lived and single-use.
- Sessions use HTTP-only cookies; production cookies are secure by default.
- Browser forms use CSRF tokens.
- Logout rejects explicit cross-origin `Origin` or `Referer` values.
- HTML, token, and error responses use no-store and basic security headers.
- Raw passwords, codes, sessions, and access tokens are never stored by the
  built-in storage.

Rate-limit `authenticateUser`, use HTTPS in production, and replace the memory
storage before deploying more than one process.

## Deliberate V1 limits

This package does not currently implement OIDC, ID tokens, refresh tokens,
registration, password reset, email verification, dynamic client registration,
MongoDB, or a client-management UI. Add those only after the OAuth-only flow is
stable.

## License

[MIT](./LICENSE)
