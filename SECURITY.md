# Security Policy

The security of `@0-auth/zero-auth` is our top priority. We appreciate and encourage responsible disclosure of vulnerabilities.

---

## Supported Versions

Only the latest major/minor releases receive active security updates and patches.

| Version | Supported          |
| ------- | ------------------ |
| `1.x`   | :white_check_mark: |
| `< 1.0` | :x:                |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via public GitHub issues.**

If you discover a potential security vulnerability in `@0-auth/zero-auth`, please report it privately through one of the following methods:

### Option 1: GitHub Security Advisory (Preferred)
Submit a private report through the GitHub Advisory interface:
👉 **[Report a vulnerability on GitHub](https://github.com/0-auth/zero-auth/security/advisories/new)**

### Option 2: Email Disclosure
Send an encrypted or direct email to:
📧 **`itsmedarshan8@gmail.com`**

Please include in your report:
- A description of the vulnerability and its potential impact.
- Step-by-step reproduction steps or a minimal proof-of-concept (PoC).
- Any affected versions or environments.
- Optional: Proposed remediation or patch.

---

## Response & Disclosure Process

1. **Acknowledgment**: We aim to acknowledge receipt of your report within **48 hours**.
2. **Assessment**: We will investigate and verify the vulnerability, keeping you informed of progress.
3. **Fix & Release**: Once confirmed, a patch will be developed, tested, and released promptly in a new npm release.
4. **Credit**: We will publicly credit your contribution in the security advisory release notes (unless you prefer to remain anonymous).

---

## Security Best Practices for Users

When using `@0-auth/zero-auth` in production applications:
- **Secrets**: Use high-entropy random secrets of at least 32 characters for `accessSecret` and `refreshSecret`. Never use hardcoded secrets.
- **HTTPS & Cookies**: Always run your production environment over HTTPS and ensure `cookies.options.secure: true` (enabled automatically when `NODE_ENV === 'production'`).
- **Token Lifespans**: Keep access token expiration short (`15m` recommended) and handle session continuity via refresh token rotation.
- **Atomic Refresh Consumption**: If enabling `refreshOptions.rotate`, implement `consumeRefreshToken` with an atomic operation such as Redis `SET NX` so concurrent requests cannot reuse the same refresh token. The legacy split hooks remain for 1.1.x compatibility but are not concurrency-safe.
