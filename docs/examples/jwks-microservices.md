# Runnable JWKS Microservices Example

Demonstrates a real-world multi-service architecture using `@0-auth/zero-auth`:
a central authentication server issuing RS256 tokens and publishing JWKS, alongside
a downstream resource microservice operating in verifier-only mode.

---

## Start the example

```bash
cd examples/express-jwks-microservices
npm install
npm start
```

This starts:
- **Central Auth Server**: `http://localhost:4000`
- **Downstream Resource Microservice**: `http://localhost:4001`

To run the automated end-to-end integration test:
```bash
npm test
```

---

## Step 1: Inspect the published JWKS

The central auth server serves its active public key(s) formatted as a JSON Web Key Set:

```bash
curl -s http://localhost:4000/.well-known/jwks.json
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

---

## Step 2: Log in on the Central Auth Server

Log in as a standard member:

```bash
login=$(curl -s -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"user123"}')

echo "$login"
```

The response includes the signed RS256 `accessToken`:
```json
{
  "user": { "id": "user-2", "email": "user@example.com", "role": "member" },
  "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGgtc2VydmVyLWtleS0yMDI2LXYxIi...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIs..."
}
```

Extract the access token:
```bash
token=$(echo "$login" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)
```

---

## Step 3: Access the Downstream Microservice

Make a request to the protected resource server on port `4001`:

```bash
curl -i http://localhost:4001/api/documents \
  -H "Authorization: Bearer $token"
```

**Response `200`:**
```json
{
  "message": "Access granted via Remote JWKS token verification!",
  "user": {
    "id": "user-2",
    "email": "user@example.com",
    "role": "member",
    "iss": "http://localhost:4000",
    "aud": "microservices-api"
  },
  "documents": [
    { "id": "doc-1", "title": "Quarterly Strategy Report" },
    { "id": "doc-2", "title": "Microservices Architecture Whitepaper" }
  ]
}
```

The downstream microservice verified the signature, issuer, and audience dynamically
without possessing any private keys.

---

## Step 4: Role-Based Access Control

Attempting to access the admin endpoint with the member token:

```bash
curl -i http://localhost:4001/api/admin/metrics \
  -H "Authorization: Bearer $token"
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

Log in as `admin@example.com` (`password: admin123`) to access the metrics route successfully.

---

## Architecture Summary

```
                      ┌────────────────────────────────────────┐
                      │    Central Auth Server (Port 4000)     │
                      │  - RS256 Private Signing Key           │
                      │  - POST /auth/login                    │
                      │  - GET /.well-known/jwks.json          │
                      └───────────────────┬────────────────────┘
                                          │
                   Dynamic Key Discovery  │ HTTP GET /.well-known/jwks.json
                   & In-Memory Caching    │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │  Resource Microservice (Port 4001)     │
                      │  - Verifier-Only Mode                  │
                      │  - ZERO Private Keys                   │
                      │  - GET /api/documents                  │
                      │  - GET /api/admin/metrics              │
                      └────────────────────────────────────────┘
```
