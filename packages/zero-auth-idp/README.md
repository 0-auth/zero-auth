# @0-auth/zero-auth-idp

> [!NOTE]
> This is an OAuth 2.0 authorization server with an optional OpenID Connect extension.
> OAuth remains the default. Configure the optional `oidc` extension when
> clients need standardized sign-in and identity claims.

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
  logoutRedirectUri: "http://localhost:4000/signed-out",
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

For a runnable MongoDB application with Docker Compose, hashed users, and a complete PKCE callback, see
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
| `GET /auth/.well-known/openid-configuration`       | OIDC metadata when enabled                 |
| `GET /auth/.well-known/jwks.json`                  | OIDC signing keys when enabled             |
| `GET /auth/userinfo`                                | OIDC user claims when enabled              |

## OIDC (opt-in)

Pass `oidc` to enable OpenID Connect discovery, signed ID tokens, JWKS, and
`/userinfo`. Add `openid` to a client's allowed scopes; authorization requests
using that scope must include a `nonce`.

```ts
const idp = createIdentityProvider({
  // ...OAuth configuration
  oidc: { signingKey: privateKey, keyId: "idp-key-2026-01" },
});
```

Production deployments must provide a stable RSA `signingKey`; development
instances generate a temporary key. The ID token contains `iss`, `sub`, `aud`,
`iat`, `exp`, `auth_time`, `nonce`, and available `email` or `name` claims.

Access tokens are opaque, short-lived Bearer tokens. Use the returned token
with `Authorization: Bearer <token>` and protect resource routes with
`idp.authenticateBearer()`.
Routes that require missing scopes return `403` with a `WWW-Authenticate`
challenge that identifies the required scope.

Pass `onEvent` to receive redacted login, denial, token, and logout events for
audit logs or metrics. Event handlers are best effort; handler failures do not
fail an authentication request, and raw passwords, codes, and tokens are never
included.

When `logoutRedirectUri` is configured, a successful logout returns `303` to
that fixed HTTP(S) URL. Without it, logout returns `204`. The fixed server-side
value prevents callers from turning logout into an open redirect.

## Hosted UI

Pass `ui.renderLogin`, `ui.renderConsent`, or `ui.renderError` to replace a
hosted page. Login renderers receive the client name and the previously entered
email after a failed attempt; passwords are never returned. Import `escapeHtml`
for every context value inserted into HTML. Same-origin stylesheets are allowed
by the package's Content Security Policy.

```ts
import { createIdentityProvider, escapeHtml } from "@0-auth/zero-auth-idp";

const ui = {
  renderLogin: ({ action, transactionId, csrfToken, clientName, email = "", error }) => `
    <link rel="stylesheet" href="/auth.css">
    <h1>Continue to ${escapeHtml(clientName)}</h1>
    ${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}
    <form method="post" action="${escapeHtml(action)}">
      <input type="hidden" name="transaction" value="${escapeHtml(transactionId)}">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <input type="email" name="email" value="${escapeHtml(email)}" required>
      <input type="password" name="password" required>
      <button>Continue</button>
    </form>`,
};
```

## Storage

The default in-memory storage is useful for local development and tests. It is
not durable and must not be used for a multi-instance deployment.

Implement `OAuthStorage` for a database or shared cache, then pass it as
`storage`. The adapter must store hashes for session, authorization-code, and
access-token values, and `consumeAuthorizationCode` must be atomic.

## Security defaults

- PKCE with `S256` is mandatory.
- Redirect URIs must match exactly and cannot contain fragments.
- Issuers must be HTTP(S) URLs without credentials, queries, or fragments; redirect
  URIs reject credential-bearing and active-content schemes.
- Authorization codes are short-lived and single-use.
- Sessions and transactions are rejected by the provider when expired, even if a
  storage adapter returns stale records.
- Sessions use HTTP-only cookies; HTTPS issuers and production environments use
  secure cookies by default.
- Browser forms use CSRF tokens.
- Logout requires a same-origin `Origin`, `Referer`, or browser fetch metadata.
- Authorization responses include the server issuer (`iss`) and metadata advertises
  that support for mix-up protection.
- OIDC is disabled unless explicitly configured; ID tokens are signed with RS256.
- Hosted pages may load stylesheets from the issuer origin; scripts remain blocked.
- HTML, token, and error responses use no-store and basic security headers.
- Raw passwords, codes, sessions, and access tokens are never stored by the
  built-in storage.

Rate-limit `authenticateUser`, use HTTPS in production, and replace the memory
storage before deploying more than one process.

## Deliberate V1 limits

This package does not currently implement refresh tokens, registration, password
reset, email verification, dynamic client registration, or a client-management
UI. Add those only after the OAuth and OIDC flows are stable.

## License

[MIT](./LICENSE)
