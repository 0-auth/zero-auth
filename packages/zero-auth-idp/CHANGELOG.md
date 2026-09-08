# Changelog

## 0.2.0 - 2026-09-08

### Added

- Expose `escapeHtml` for safe custom hosted pages.
- Include the client name and previously entered email in login UI context.
- Support an optional fixed HTTP(S) redirect after logout.
- Add issuer identification to authorization responses and metadata.
- Add redacted lifecycle events for audit logs and metrics.
- Add opt-in OIDC discovery, RS256 ID tokens, JWKS, and userinfo.
- Include required scopes in insufficient-scope bearer challenges.

### Changed

- Allow same-origin stylesheets on hosted pages while continuing to block scripts.
- Enforce expiry and request-size limits inside the provider.
- Reject unsafe issuer and redirect URI configuration.
- Apply security headers to OAuth error redirects and secure cookies for HTTPS issuers.

## 0.1.0 - 2026-09-05

### Added

- Initial OAuth authorization server with hosted login and consent UI.
