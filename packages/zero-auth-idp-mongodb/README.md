# @0-auth/zero-auth-idp-mongodb

> [!NOTE]
> This package only provides storage for `@0-auth/zero-auth-idp`. It does not
> create users, hash passwords, or expose a MongoDB user model.
> This adapter is not published yet. Use the repository example until release.
> Unreleased schema change: `expiresAt` is now stored as a BSON date. Convert
> numeric records from the earlier scaffold before reusing that development data.

MongoDB storage for the self-hosted OAuth authorization server. The core IdP
package stays database-independent; this adapter persists sessions, temporary
OAuth transactions, authorization codes, and access tokens.

## Install (after release)

```bash
npm install @0-auth/zero-auth-idp @0-auth/zero-auth-idp-mongodb mongodb@6
```

## Usage

```ts
import express from "express";
import { MongoClient } from "mongodb";
import { createIdentityProvider } from "@0-auth/zero-auth-idp";
import { createMongoOAuthStorage } from "@0-auth/zero-auth-idp-mongodb";
import { authenticateUser } from "./users.js"; // Your application's password verification.

const client = new MongoClient(process.env.MONGODB_URI!);
await client.connect();

const storage = createMongoOAuthStorage(client.db("my-app"));
await storage.ensureIndexes();

const idp = createIdentityProvider({
  issuer: "https://example.com/auth",
  storage,
  clients: [
    {
      clientId: "my-app",
      clientType: "public",
      redirectUris: ["https://example.com/callback"],
      allowedScopes: ["profile"],
    },
  ],
  authenticateUser,
});

const app = express();
app.use("/auth", idp.router());
app.listen(3000);
```

The application-provided `authenticateUser({ email, password })` must verify a
password hash and return `{ id, email }`, or `null` for invalid credentials.
The runnable example below includes a complete implementation.

## Collections

The adapter creates four collections using the `zero_auth_idp_` prefix:

- `zero_auth_idp_sessions`
- `zero_auth_idp_transactions`
- `zero_auth_idp_authorization_codes`
- `zero_auth_idp_access_tokens`

Pass `{ collectionPrefix: "my_prefix" }` to change the prefix. Call
`ensureIndexes()` during application startup. Each collection receives a TTL
index on `expiresAt`. The adapter writes this field as a BSON date and converts it
back to milliseconds on reads, preserving the core package's storage interface.
MongoDB cleanup is asynchronous; session, transaction, and code queries reject
expired records immediately. The core checks access-token expiration.

The earlier unreleased scaffold stored numeric dates, which MongoDB TTL indexes
cannot clean. Existing development records from that scaffold need their
`expiresAt` converted to BSON dates before using this adapter; no automatic
database migration runs on startup.

See the [runnable MongoDB example](../../examples/express-idp/README.md) for Docker
Compose, hashed user authentication, a complete PKCE client, and restart testing.

## Integration tests

Set `MONGODB_URI` to a disposable/test MongoDB instance and run
`npm run test:integration --workspace @0-auth/zero-auth-idp-mongodb` from the
repository root. Tests use a uniquely named database and delete it afterward.
They verify actual TTL deletion in all four collections, numeric API round trips,
concurrent code consumption, and revocation across connections. The TTL test waits
up to 90 seconds for background cleanup. Without `MONGODB_URI`, regular unit tests
skip integration.

## Security behavior

- Session, authorization-code, and access-token values are stored by their
  hashes supplied by the core package.
- Authorization-code consumption uses MongoDB `findOneAndDelete`, so only one
  concurrent token exchange can consume a valid code.
- Client, redirect URI, PKCE, scope, and user validation remain in the core
  IdP package.
- The adapter does not store passwords or application business data.

The adapter requires MongoDB driver 6.x so it remains compatible with Node.js 18. Use a database with appropriate TLS, authentication, backups, and network
access controls in production.

## License

[MIT](./LICENSE)
