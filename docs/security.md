# Security checklist

`zero-auth` signs and verifies tokens, extracts them from requests, protects
routes, and supports refresh-token rotation. Your application still owns
credential handling, transport security, abuse prevention, and authorization
policy.

## Secrets

- Use separate access and refresh secrets.
- Use random secrets of at least 32 characters.
- Store secrets in a deployment secret manager.
- Never commit secrets, print them, or include them in error responses.
- Rotate secrets deliberately; changing a secret invalidates tokens signed with
  the old value.

## Passwords and login

- Hash passwords with a password hashing algorithm such as Argon2id or bcrypt.
- Never put passwords in JWT claims.
- Rate-limit login, registration, and refresh endpoints.
- Use generic login failure messages to avoid account enumeration.
- Require re-authentication for sensitive account changes.

Password hashing and login policy are application responsibilities; this
package does not store users or validate passwords.

## Tokens

- Keep access tokens short-lived, such as `15m`.
- Use longer-lived refresh tokens only with a revocation strategy.
- Enable rotation when refresh-token replay is a concern.
- Store rotation state in Redis or a database when running multiple instances.
- Do not log or expose complete access or refresh tokens.
- Reject tokens signed with the wrong secret or intended token type.

## Cookies

For browser applications, start with:

```ts
cookies: {
  options: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
  },
}
```

Use HTTPS in production. Match cookie `domain` and `path` to the routes that
need the cookie, and use `sameSite: "none"` only for a required cross-site
flow with HTTPS.

HTTP-only cookies reduce token exposure to JavaScript, but they do not remove
CSRF risk. Cookie-authenticated state-changing requests need CSRF protection or
an equivalent origin/request validation strategy. See OWASP's
[CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

## CORS and origins

- Allow only known frontend origins.
- Do not combine `Access-Control-Allow-Origin: *` with credentials.
- Allow credentials only when cookie authentication requires it.
- Validate the `Origin` header for sensitive browser operations where
  appropriate.

## Authorization

- Authenticate before authorizing:

```ts
app.get("/admin", auth.protect(), auth.authorize(["admin"]), handler);
```

- Check resource ownership in application code; a valid role does not
  automatically grant access to every record.
- Prefer explicit allow-lists for roles and permissions.
- Test both allowed and denied access paths.

## Operations

- Put TLS termination behind a trusted proxy and configure Express proxy trust
  carefully.
- Add request IDs and log error codes, not token contents.
- Monitor repeated invalid-token, login, and refresh-reuse events.
- Keep dependencies updated and run the test suite before deployment.

For broader authentication and session guidance, see OWASP's
[Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
and [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
