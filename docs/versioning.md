# Versioning and migrations

zero-auth follows [Semantic Versioning](https://semver.org/):

- Patch releases fix bugs without intentionally changing the public API.
- Minor releases add backwards-compatible features.
- Major releases may require code or configuration changes.

Check the installed and published versions before upgrading:

~~~bash
npm list @0-auth/zero-auth
npm view @0-auth/zero-auth version
~~~

## v1.2.0 upgrade notes

v1.2.0 adds opt-in browser CSRF protection and fine-grained permission
authorization:

- Mount <code>auth.csrf()</code> for cookie-authenticated state-changing requests.
- Expose an endpoint that calls <code>auth.csrfToken(res)</code>.
- Send the returned token in the configured CSRF header.
- Use <code>auth.authorizePermissions([...])</code> after <code>auth.protect()</code>.
- Every permission passed to <code>authorizePermissions()</code> is required.

The legacy <code>isRevoked</code> and <code>revokeRefreshToken</code> hooks remain
available for compatibility, but emit a warning and are not concurrency-safe.
Use <code>consumeRefreshToken</code> for rotated refresh tokens.

## Upgrade safely

1. Read the release notes for the target version.
2. Update the package in a branch.
3. Run the application test suite and TypeScript checks.
4. Exercise login, protected routes, refresh, logout, and authorization.
5. Exercise CSRF-protected cookie writes if cookies are enabled.
6. Deploy gradually if refresh-token behavior or cookie settings changed.

~~~bash
npm install @0-auth/zero-auth@latest
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
~~~

Keep <code>package-lock.json</code> or your package-manager lockfile committed
so CI and local development use the same dependency tree.

## Configuration migrations

Compare these values explicitly:

- Access and refresh secrets
- Access and refresh expiration times
- Cookie names, paths, domains, and secure settings
- CSRF cookie name, header name, and protected methods
- <code>refreshOptions.rotate</code>
- Refresh-store atomicity and TTLs
- Role and permission claims

Changing a signing secret invalidates tokens signed with the old value. Plan a
coordinated sign-in or token migration before changing secrets in production.

Changing cookie names or paths can make existing browser sessions appear logged
out. Deploy compatible cookie handling or ask users to sign in again.

## Release compatibility checklist

Before adopting a new version, confirm:

- The runtime satisfies the package Node.js engine requirement.
- Express is installed when middleware is used.
- The release does not change the token claims your clients depend on.
- Rotation stores remain compatible with the refresh lifecycle.
- Cookie and CSRF settings match the deployed frontend origins.
- Error codes are handled by clients without string-matching messages.

## Migration template

Use this format for future breaking changes:

~~~~md
## From 1.x to 2.x

### What changed
- ...

### Before
~~~ts
// old API
~~~

### After
~~~ts
// new API
~~~

### Required deployment steps
1. ...
~~~~

Document the user-visible effect, the exact code change, and any token, cookie,
or refresh-state consequences. Breaking changes must also be placed in the
attention section at the start of the package README.
