# Express JWKS & Microservices Architecture Example

Demonstrates a real-world **microservices authentication architecture** using `@0-auth/zero-auth`.

- **Central Auth Service (Port 4000)**: Holds the private key, signs RS256 JWT tokens on login, and publishes public verification keys via standard `GET /.well-known/jwks.json` using `auth.jwksHandler()`.
- **Downstream Resource Microservice (Port 4001)**: Operates in **Verifier-Only Mode** with **zero private keys**. It dynamically fetches and caches public keys from the central auth server's JWKS endpoint using `jwksUri`.
- **Zero-Downtime Key Rotation**: Demonstrates how key rotation on the central auth server seamlessly propagates to downstream microservices with automatic caching and rate-limiting cooldown.

---

## Architecture Diagram

```
+-------------------------------------------------------------+
|                 Central Auth Server (Port 4000)             |
|  - Holds RSA Private Key                                    |
|  - Signs JWTs on POST /auth/login                           |
|  - Publishes GET /.well-known/jwks.json (auth.jwksHandler)  |
+------------------------------+------------------------------+
                               |
                               | Public Keys (JWKS JSON)
                               v
+-------------------------------------------------------------+
|             Downstream Resource Service (Port 4001)         |
|  - ZERO Private Keys (Zero Signing Capability)              |
|  - Verifies tokens via jwksUri                              |
|  - In-memory cache + rate-limited refetch cooldown          |
|  - Protected routes: GET /api/documents, GET /api/admin/... |
+-------------------------------------------------------------+
```

---

## Setup & Running

### 1. Install Dependencies
From the repository root:
```bash
npm install
```

Or within this directory:
```bash
cd examples/express-jwks-microservices
npm install
```

### 2. Start Both Services
```bash
npm start
```

This starts:
- Central Auth Server on **http://localhost:4000**
- Downstream Resource Microservice on **http://localhost:4001**

### 3. Run Automated End-to-End Tests
```bash
npm test
```

---

## Manual Walkthrough (with cURL)

### Step 1: Inspect the Published JWKS
```bash
curl http://localhost:4000/.well-known/jwks.json
```
**Response `200`:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "auth-server-key-2026-v1",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Step 2: Log In as a User on the Central Auth Server
```bash
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"user123"}'
```
**Response `200`:**
```json
{
  "user": { "id": "user-2", "email": "user@example.com", "role": "member" },
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

### Step 3: Access Protected Route on the Downstream Microservice
Pass the `accessToken` obtained from the central auth server:
```bash
curl http://localhost:4001/api/documents \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```
**Response `200`:**
```json
{
  "message": "Access granted via Remote JWKS token verification!",
  "user": {
    "id": "user-2",
    "email": "user@example.com",
    "role": "member"
  },
  "documents": [...]
}
```

### Step 4: Role-Based Access Control (RBAC)
Attempting to access an admin-only endpoint with a `member` token:
```bash
curl http://localhost:4001/api/admin/metrics \
  -H "Authorization: Bearer <MEMBER_TOKEN>"
```
**Response `403`:**
```json
{
  "error": {
    "code": "AUTH_FORBIDDEN",
    "message": "Forbidden. You do not have permission to access this resource.",
    "statusCode": 403
  }
}
```

Log in as `admin@example.com` (`password: admin123`), then access `/api/admin/metrics` to receive `200 OK`.

---

## Code Overview

### Central Auth Server (`src/auth-server.ts`)
```ts
import { createAuth } from "@0-auth/zero-auth";

const auth = createAuth({
  algorithm: "RS256",
  keyId: "auth-server-key-2026-v1",
  privateKey: process.env.JWT_PRIVATE_KEY!,
  publicKey: process.env.JWT_PUBLIC_KEY!,
  jwt: {
    issuer: "http://localhost:4000",
    audience: "microservices-api",
  },
});

// Expose standard JWKS endpoint
app.get("/.well-known/jwks.json", auth.jwksHandler());
```

### Downstream Microservice (`src/resource-server.ts`)
```ts
import { createAuth } from "@0-auth/zero-auth";

// Verifier-Only Mode: Zero private keys needed!
const auth = createAuth({
  jwksUri: "http://localhost:4000/.well-known/jwks.json",
  jwt: {
    issuer: "http://localhost:4000",
    audience: "microservices-api",
  },
  jwks: {
    cacheMaxAge: 600_000,     // 10 minutes cache
    cooldownDuration: 30_000, // 30 seconds cooldown between rate-limited refetches
    timeoutDuration: 5_000,   // 5 seconds network timeout
  },
});

app.get("/api/documents", auth.protect(), (req, res) => {
  res.json({ user: req.user });
});
```
