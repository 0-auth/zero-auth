# 0-auth

Monorepo for the `@0-auth` packages.

## Packages

- [`@0-auth/zero-auth`](./packages/zero-auth/README.md) — JWT authentication
  for Node.js and Express APIs.
- [`@0-auth/zero-auth-idp`](./packages/zero-auth-idp/README.md) — OAuth authorization
  server with backend-hosted login and consent UI.
- [`@0-auth/zero-auth-idp-mongodb`](./packages/zero-auth-idp-mongodb/README.md) —
  persistent MongoDB storage for the authorization server (not published yet).

Try the [runnable OAuth/MongoDB example](./examples/express-idp/README.md) with
Docker Compose, a complete PKCE client, and application restart tests.

## Development

```bash
npm install
npm test
npm run typecheck
npm run build
npm run docs:build
```

## Documentation

- [Documentation site](https://zero-auth.netlify.app/)
- [Release process](./docs/releasing.md)
- [Security policy](./SECURITY.md)

## License

MIT. See [packages/zero-auth/LICENSE](./packages/zero-auth/LICENSE).
