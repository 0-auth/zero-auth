# Changelog

Package-specific changes are tracked in each package changelog:

- [`@0-auth/zero-auth`](./packages/zero-auth/CHANGELOG.md)

## Repository changes

### 1.6.0 - 2026-09-28

- Add asymmetric key support (RS256, ES256, EdDSA) and remote JWKS verification/publisher to `@0-auth/zero-auth`.
- Add runnable JWKS microservices architecture example (`examples/express-jwks-microservices`).
- Update documentation site with Asymmetric & JWKS guide, example walkthrough, and TypeDoc API exports.

### 1.5.0 - 2026-09-15

- Add `refreshOptions.resolveUser` to `@0-auth/zero-auth`.

### 1.4.1 - 2026-09-05

- Harden Redis refresh-token family revocation against late replacement
  registration and add live concurrent-rotation coverage.
- Stop the REST example test from printing complete JWT values.

### 1.3.0 - 2026-09-03

- Migrate the repository to an npm-workspaces layout without changing the
  published `@0-auth/zero-auth` package name or API.
