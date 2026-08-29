# Changelog

## Unreleased

- Expand documentation for authentication flows, CSRF, permissions,
  refresh-token rotation, deployment, testing, clients, and releases.
- Add CI documentation-build validation.

## 1.2.0 - 2026-08-29

- Add signed double-submit CSRF protection for cookie-authenticated requests.
- Add `auth.csrf()` middleware and `auth.csrfToken(res)` token setup.
- Add `auth.authorizePermissions()` middleware for fine-grained access checks.
- Add the `AUTH_CSRF_INVALID` error code and document the browser/cURL flow.

## 1.1.3 - 2026-08-25

- Add a prominent README section for breaking changes and upgrade notes.
- Document the refresh-rotation compatibility warning at the start of the README.

## 1.1.2 - 2026-08-24

- Add atomic refresh-token consumption for concurrency-safe rotation.
- Keep the legacy `isRevoked` and `revokeRefreshToken` hooks as a warned fallback.
- Reject incomplete rotation stores instead of silently accepting unsafe configuration.
- Add concurrency, legacy fallback, and production-warning coverage.
- Harden and document the deployable Express + Redis cookie-auth example.
