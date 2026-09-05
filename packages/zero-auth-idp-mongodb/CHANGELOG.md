# Changelog

## Unreleased

### Added

- MongoDB storage adapter with TTL indexes and atomic authorization-code consumption.
- Real MongoDB integration tests for expiration, persistence, concurrency, and revocation.
- Runnable Express/MongoDB example with hashed users, PKCE callback, and Docker Compose.

### Fixed

- Store `expiresAt` as a BSON date so MongoDB actually removes expired records;
  convert it back to milliseconds for the core API. Earlier unreleased numeric
  development records require conversion before reuse.
