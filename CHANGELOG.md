# Changelog

Package-specific changes are tracked in each package changelog:

- [`@0-auth/zero-auth`](./packages/zero-auth/CHANGELOG.md)

## Repository changes

### 1.4.1 - 2026-09-05

- Harden Redis refresh-token family revocation against late replacement
  registration and add live concurrent-rotation coverage.
- Stop the REST example test from printing complete JWT values.

### 1.3.0 - 2026-09-03

- Migrate the repository to an npm-workspaces layout without changing the
  published `@0-auth/zero-auth` package name or API.
