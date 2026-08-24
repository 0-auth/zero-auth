# Changelog

## 1.1.2 - 2026-08-24

- Add atomic refresh-token consumption for concurrency-safe rotation.
- Keep the legacy `isRevoked` and `revokeRefreshToken` hooks as a warned fallback.
- Reject incomplete rotation stores instead of silently accepting unsafe configuration.
- Add concurrency, legacy fallback, and production-warning coverage.
- Harden and document the deployable Express + Redis cookie-auth example.
