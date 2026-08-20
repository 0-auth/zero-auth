# Versioning and migrations

`zero-auth` follows [Semantic Versioning](https://semver.org/):

- **Patch** releases fix bugs without intentionally changing the public API.
- **Minor** releases add backwards-compatible features.
- **Major** releases may require code or configuration changes.

Check the package version before upgrading:

```bash
npm view @0-auth/zero-auth version
npm list @0-auth/zero-auth
```

## Upgrade safely

1. Read the release notes for the target version.
2. Update the package in a branch.
3. Run the application test suite and TypeScript checks.
4. Exercise login, protected routes, refresh, logout, and role checks.
5. Deploy gradually if refresh-token behavior or cookie settings changed.

```bash
npm install @0-auth/zero-auth@latest
npm test
npm run typecheck
npm run build
```

Keep `package-lock.json` or your package manager lockfile committed so CI and
local development use the same dependency tree.

## Configuration migrations

When changing auth configuration, compare these values explicitly:

- `accessSecret` and `refreshSecret`
- access and refresh expiration times
- cookie names and cookie options
- `refreshOptions.rotate`
- revocation-store behavior

Changing a signing secret invalidates tokens signed with the old secret. Plan a
coordinated sign-in or token migration before changing secrets in production.

Changing cookie names or paths can make existing browser sessions appear logged
out. Deploy compatible cookie handling or ask users to sign in again.

## Migration template

Use this format for future breaking changes:

~~~md
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
~~~

Document the user-visible effect, the exact code change, and any token or
cookie consequences.
