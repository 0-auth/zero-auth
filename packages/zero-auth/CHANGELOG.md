# Changelog

## 1.6.0 - 2026-09-28

### Added

- **Asymmetric Key Cryptography**:
  - Support for asymmetric algorithms: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and `EdDSA` (Ed25519) via PKCS#8 / SPKI PEM strings or `CryptoKey`.
  - Configurable `keyId` to emit the `kid` header claim in signed JWTs.
  - Dedicated Verifier-Only mode allowing downstream microservices and gateways to verify tokens using only the public key with zero signing capability.
- **Remote JWKS Verification & Publisher**:
  - Dynamic verification against remote JWKS endpoints (`jwksUri: string | URL`), compatible with central auth servers and third-party Identity Providers (Clerk, Auth0, Firebase, Google, AWS Cognito).
  - Built-in in-memory caching (`cacheMaxAge`), rate-limited cooldown (`cooldownDuration`), and request timeout options (`timeoutDuration`) via `jwks: RemoteJwksConfig`.
  - Zero-downtime key rotation: automated refetching when encountering an unobserved Key ID (`kid`).
  - JWKS publisher route handler: `auth.jwksHandler()` serves public keys at `/.well-known/jwks.json` with automated `Content-Type` and `Cache-Control` headers.
  - Programmatic JWKS export: `auth.getJwks()` with memoized JWK caching.
  - Standalone utility functions: `createJwksResolver()` and `exportPublicKeyToJwk()`.
- **New Microservices Architecture Example**:
  - Added runnable example `examples/express-jwks-microservices` demonstrating central RS256 token issuance and JWKS publishing alongside a downstream verifier-only microservice.
- **Documentation**:
  - Added dedicated guide `docs/guides/asymmetric-and-jwks.md`.
  - Added runnable example guide `docs/examples/jwks-microservices.md`.
  - Updated configuration reference and VitePress navigation.

## 1.5.0 - 2026-09-15

### Added

- Add `refreshOptions.resolveUser` to reload current claims or reject an account
  before issuing refreshed tokens.

## 1.4.1 - 2026-09-05

### Security

- Prevent Redis refresh-token family registrations from winning a race with
  family revocation.
- Add concurrent Redis rotation coverage to the deployable example.
- Stop the REST example test from printing complete JWT values.

## 1.4.0 - 2026-09-05

### Added

- Add the optional-dependency-free `createRedisRevocationStore()` helper for
  ioredis-compatible clients and atomic refresh-token rotation.

## 1.3.0 - 2026-09-03

### Added

- Add optional JWT issuer, audience, clock-tolerance, and `nbf` validation.
- Add the public `RefreshTokenStore` contract for automatic rotation wiring.

### Documentation

- Expand documentation for authentication flows, CSRF, permissions,
  refresh-token rotation, deployment, testing, clients, and releases.
- Add CI documentation-build validation.
- Surface the new JWT policy, refresh-store integration, and legacy fallback
  guidance in the README and documentation site.

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
