# Changelog

This page tracks user-visible changes to the packages in this repository.
Package release details live in
[`packages/zero-auth/CHANGELOG.md`](https://github.com/0-auth/zero-auth/blob/master/packages/zero-auth/CHANGELOG.md).
The repository [CHANGELOG.md](https://github.com/0-auth/zero-auth/blob/master/CHANGELOG.md)
tracks repository-level changes.

## Unreleased

### Security

- Prevent Redis refresh-token family registrations from winning a race with
  family revocation.
- Add concurrent Redis rotation coverage to the deployable example.

## 1.4.0 — 2026-09-05

### Added

- Add the optional-dependency-free `createRedisRevocationStore()` helper for
  ioredis-compatible clients and atomic refresh-token rotation.

## 1.3.0 — 2026-09-03

### Added

- Add optional JWT issuer, audience, clock-tolerance, and `nbf` validation.
- Add the public <code>RefreshTokenStore</code> contract for automatic rotation
  wiring.

### Documentation

- Expand documentation for authentication flows, CSRF, permissions,
  refresh-token rotation, deployment, testing, clients, and releases.
- Add CI documentation-build validation.
- Add this dedicated documentation changelog page.
- Surface the new JWT policy, refresh-store integration, and legacy fallback
  guidance in the README and documentation site.

## 1.2.0 — 2026-08-29

- Add signed double-submit CSRF protection for cookie-authenticated requests.
- Add <code>auth.csrf()</code> middleware and
  <code>auth.csrfToken(res)</code> token setup.
- Add <code>auth.authorizePermissions()</code> middleware for fine-grained
  access checks.
- Add the <code>AUTH_CSRF_INVALID</code> error code and document the
  browser/cURL flow.

## 1.1.3 — 2026-08-25

- Add a prominent README section for breaking changes and upgrade notes.
- Document the refresh-rotation compatibility warning at the start of the
  README.

## 1.1.2 — 2026-08-24

- Add atomic refresh-token consumption for concurrency-safe rotation.
- Keep the legacy <code>isRevoked</code> and
  <code>revokeRefreshToken</code> hooks as a warned fallback.
- Reject incomplete rotation stores instead of silently accepting unsafe
  configuration.
- Add concurrency, legacy fallback, and production-warning coverage.
- Harden and document the deployable Express + Redis cookie-auth example.

## Release process

For versioning, release checks, GitHub releases, and npm publishing, see
[Release and maintenance](/releasing). Breaking changes must also be called
out in the attention section at the start of the package README.
