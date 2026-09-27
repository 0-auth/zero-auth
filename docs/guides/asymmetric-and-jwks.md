# Asymmetric Keys & Remote JWKS

Asymmetric cryptographic algorithms (`RS256`, `ES256`, `EdDSA`, `PS256`) allow a central
authentication authority to sign JWTs with a private key while downstream
microservices and API gateways verify tokens using only the public key.

With **Remote JWKS Verification**, downstream services dynamically fetch and cache
public keys from a central `/.well-known/jwks.json` endpoint, enabling zero-downtime
key rotation with zero private key distribution.

---

## Central Auth Service (JWKS Publisher)

The central authentication service holds both the private signing key and the
public verification key. It issues tokens upon user login and serves a standard
JWKS endpoint using `auth.jwksHandler()`.

### Configuration

```ts
import express from "express";
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  algorithm: "RS256",
  keyId: "auth-server-key-2026-v1",
  privateKey: process.env.JWT_PRIVATE_KEY!, // PKCS#8 PEM string or CryptoKey
  publicKey: process.env.JWT_PUBLIC_KEY!,   // SPKI PEM string or CryptoKey
  jwt: {
    issuer: "https://auth.example.com",
    audience: "api.example.com",
  },
  accessExpiresIn: "15m",
});

const app = express();

// Serve the JWKS public keys at standard endpoint
app.get("/.well-known/jwks.json", auth.jwksHandler());

// Issue signed RS256 token pairs on login
app.post("/auth/login", async (req, res) => {
  const tokenPair = await auth.generateTokenPair({
    id: "user-123",
    email: "user@example.com",
    role: "admin",
  });
  res.json(tokenPair);
});
```

### Programmatic JWKS Export

You can also export the JWKS programmatically using `auth.getJwks()`:

```ts
const jwks = await auth.getJwks();
// {
//   keys: [
//     {
//       kty: "RSA",
//       kid: "auth-server-key-2026-v1",
//       alg: "RS256",
//       use: "sig",
//       n: "...",
//       e: "AQAB"
//     }
//   ]
// }
```

---

## Downstream Microservices (Remote JWKS Consumer)

Downstream microservices run in **Verifier-Only Mode**. They require **no private keys**
and cannot forge or sign tokens. Verification keys are resolved dynamically from
the remote `jwksUri`.

### Configuration

```ts
import express from "express";
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  jwt: {
    issuer: "https://auth.example.com",
    audience: "api.example.com",
  },
  jwks: {
    cacheMaxAge: 600_000,       // Cache keys in memory for 10 minutes (default)
    cooldownDuration: 30_000,   // Wait 30s before refetching on unknown kid (rate limiting)
    timeoutDuration: 5_000,     // Network timeout in ms
  },
});

const app = express();

// Protect endpoints using standard zero-auth middleware
app.get("/api/orders", auth.protect(), (req, res) => {
  res.json({ orders: [], userId: req.user.id });
});

// Enforce role-based access control
app.get("/api/admin/metrics", auth.protect(), auth.authorize(["admin"]), (req, res) => {
  res.json({ status: "healthy", adminId: req.user.id });
});

app.use(auth.errorHandler);
```

---

## Static Verifier-Only Mode

If you prefer to bundle or mount a static public key rather than making HTTP
requests to a remote JWKS endpoint, supply only `publicKey`:

```ts
const auth = createAuth({
  algorithm: "ES256",
  publicKey: process.env.JWT_PUBLIC_KEY!, // SPKI PEM or CryptoKey
  jwt: {
    issuer: "https://auth.example.com",
    audience: "api.example.com",
  },
});
```

Calling `auth.generateAccessToken()` or `auth.generateRefreshToken()` in this mode
throws a descriptive configuration error.

---

## Third-Party Identity Providers (IDPs)

Because `jwksUri` follows OpenID Connect (OIDC) standards, you can use `zero-auth`
directly with third-party auth platforms:

### Clerk

```ts
const auth = createAuth({
  jwksUri: "https://<your-clerk-domain>.clerk.accounts.dev/.well-known/jwks.json",
});
```

### Auth0

```ts
const auth = createAuth({
  jwksUri: "https://<your-tenant>.auth0.com/.well-known/jwks.json",
  jwt: {
    issuer: "https://<your-tenant>.auth0.com/",
    audience: "https://api.mycompany.com",
  },
});
```

### Firebase Authentication / Google Cloud

```ts
const auth = createAuth({
  jwksUri: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
  jwt: {
    issuer: "https://securetoken.google.com/<project-id>",
    audience: "<project-id>",
  },
});
```

### AWS Cognito

```ts
const auth = createAuth({
  jwksUri: "https://cognito-idp.<region>.amazonaws.com/<userPoolId>/.well-known/jwks.json",
  jwt: {
    issuer: "https://cognito-idp.<region>.amazonaws.com/<userPoolId>",
  },
});
```

---

## Key Rotation Best Practices

1. **Deploy New Key First**: Add the new public key to the JWKS endpoint alongside the current key.
2. **Switch Signing Key**: Switch the auth server to sign new JWTs with the new private key and updated `kid`.
3. **Grace Period**: Keep the previous public key in the JWKS until all previously issued tokens have expired (e.g., 15 minutes for access tokens).
4. **Retire Old Key**: Remove the retired public key from the JWKS.
