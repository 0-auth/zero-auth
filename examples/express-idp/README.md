# Express OAuth authorization server example

This is a small runnable application using
`@0-auth/zero-auth-idp` inside its existing Express backend. It demonstrates
the hosted login and consent UI, Authorization Code + PKCE, an opaque access
token, and a protected API route.

The demo uses in-memory storage and a hard-coded user. Replace both before
production.

## Run from this repository

Build the package first so the local `file:` dependency has its `dist/` files:

```bash
npm run build --workspace @0-auth/zero-auth-idp
cd examples/express-idp
npm install
npm start
```

The server listens on `http://localhost:3001`.

## Check metadata

```bash
curl.exe http://localhost:3001/auth/.well-known/oauth-authorization-server
```

## Browser flow

Generate a PKCE verifier and challenge in your client. For a quick local test,
this PowerShell snippet creates both:

```powershell
$verifier = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64url'))"
$challenge = node -e "process.stdout.write(require('crypto').createHash('sha256').update(process.argv[1]).digest('base64url'))" $verifier
```

Open this URL in a browser, replacing the two PowerShell variables with their
values:

```text
http://localhost:3001/auth/authorize?response_type=code&client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&scope=profile&state=demo-state&code_challenge=<challenge>&code_challenge_method=S256
```

Sign in with:

```text
Email:    user@example.com
Password: correct-horse
```

Approve the consent screen. The browser redirects to `/callback`; the demo
only reports whether it received a code. A real client exchanges that code at
the token endpoint.

## Complete the flow with curl

The following commands use the verifier and challenge from above. Keep the
authorization response headers visible and copy the `code` query parameter
from the final `Location` header without logging or sharing it.

```powershell
curl.exe -i -c cookies.txt -b cookies.txt "http://localhost:3001/auth/authorize?response_type=code&client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&scope=profile&state=demo-state&code_challenge=$challenge&code_challenge_method=S256"
```

Follow the `Location` headers with the cookie jar:

```powershell
curl.exe -i -c cookies.txt -b cookies.txt "http://localhost:3001/auth/login?transaction=<transaction>"
```

Read the hidden `transaction` and `csrf_token` fields from the HTML, then
submit the hosted login form:

```powershell
curl.exe -i -c cookies.txt -b cookies.txt -X POST http://localhost:3001/auth/login `
  -H "Content-Type: application/x-www-form-urlencoded" `
  --data "transaction=<transaction>&csrf_token=<login-csrf>&email=user%40example.com&password=correct-horse"
```

Read the consent form fields, then approve it:

```powershell
curl.exe -i -c cookies.txt -b cookies.txt -X POST http://localhost:3001/auth/consent `
  -H "Content-Type: application/x-www-form-urlencoded" `
  --data "transaction=<transaction>&csrf_token=<consent-csrf>&decision=allow"
```

Exchange the returned code:

```powershell
$tokenResponse = curl.exe -s -X POST http://localhost:3001/auth/token `
  -H "Content-Type: application/x-www-form-urlencoded" `
  --data "grant_type=authorization_code&client_id=demo-app&code=<code>&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&code_verifier=$verifier"
$tokenResponse
```

Use the returned access token on the protected route:

```powershell
curl.exe http://localhost:3001/api/profile -H "Authorization: Bearer <access-token>"
```

Expected response:

```json
{ "userId": "user-1", "scopes": ["profile"] }
```

The authorization code is single-use. Repeating the token request returns
`invalid_grant`.
