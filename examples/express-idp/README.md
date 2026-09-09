# Express OIDC example with MongoDB

> [!NOTE]
> The example requires MongoDB, `DEMO_PASSWORD` (at least 12 characters), and a
> base64-encoded PKCS8 RSA private key. It is a deployable OpenID Connect
> demonstration with one seeded user and self-registration, not a production
> identity directory.

One Express backend demonstrates three roles: an authorization server with hosted
login/consent, an OIDC client, and a protected resource API. MongoDB persists each
role's state so the application can restart without signing everyone out. Its
container installs the published packages and runs without the monorepo.

## Run with Docker Compose

From the repository root, using PowerShell:

```powershell
$env:DEMO_PASSWORD = "choose-a-long-local-demo-password"
$env:OIDC_PRIVATE_KEY_BASE64 = node -e "const {generateKeyPairSync}=require('node:crypto');const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});process.stdout.write(Buffer.from(privateKey.export({type:'pkcs8',format:'pem'})).toString('base64'))"
docker compose -p zero-auth-idp-example -f examples/express-idp/docker-compose.yml up --build -d --wait
```

In Bash, export both values before the same Compose command:

```bash
export DEMO_PASSWORD='choose-a-long-local-demo-password'
export OIDC_PRIVATE_KEY_BASE64="$(node -e 'const {generateKeyPairSync}=require("node:crypto");const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});process.stdout.write(Buffer.from(privateKey.export({type:"pkcs8",format:"pem"})).toString("base64"))')"
```

Alternatively, copy `.env.example` to `.env` in this example directory and set
both values. Never commit that file or the private key.

Open [http://localhost:3001](http://localhost:3001), click **Continue to identity
provider**, sign in as `user@example.com` with your configured password, and
approve consent. Demo app then renders the protected profile response without
displaying the access or ID token. You can also choose **Create account** first
and use that email for the same flow.

MongoDB is accessible only on the Compose network; it does not take over your
existing host port 27017. The app is exposed on localhost port 3001. Its MongoDB
volume persists through `docker compose down`. Return to `/` for the revoke
and logout buttons.

Stop the example without deleting its data:

```powershell
docker compose -p zero-auth-idp-example -f examples/express-idp/docker-compose.yml down
```

## Run with Node.js 22 and an existing MongoDB

From the repository root:

```powershell
cd examples/express-idp
npm ci
$env:MONGODB_URI = "mongodb://127.0.0.1:27017"
$env:MONGODB_DATABASE = "zero_auth_idp_example"
$env:DEMO_PASSWORD = "choose-a-long-local-demo-password"
$env:OIDC_PRIVATE_KEY_BASE64 = node -e "const {generateKeyPairSync}=require('node:crypto');const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});process.stdout.write(Buffer.from(privateKey.export({type:'pkcs8',format:'pem'})).toString('base64'))"
npm run build
npm start
```

For Node execution, export environment variables as shown; `npm start` does not
automatically load `.env`.

| Variable                  | Default / requirement                                               |
| ------------------------- | ------------------------------------------------------------------- |
| `DEMO_PASSWORD`           | Required, at least 12 characters; used only when seeding a new user |
| `OIDC_PRIVATE_KEY_BASE64` | Required base64-encoded PKCS8 RSA private key                       |
| `OIDC_KEY_ID`             | `demo-key-1`; change when rotating the signing key                  |
| `MONGODB_URI`             | `mongodb://127.0.0.1:27017`                                         |
| `MONGODB_DATABASE`        | `zero_auth_idp_example`                                             |
| `PORT`                    | `3001`                                                              |
| `PUBLIC_ORIGIN`           | `http://localhost:<PORT>`, without a trailing slash                 |
| `TRUST_PROXY`             | `0`; use `1` only behind one trusted proxy hop                      |

Seeding is idempotent. The password is stored as a salted scrypt hash in the
application's `demo_users` collection. Changing `DEMO_PASSWORD` after the first
run does not overwrite an existing password. The IdP adapter never manages users.

## Register a user

Open `/register`, enter an email and a password of at least 12 characters, then
continue to the identity provider. Registration normalizes email addresses,
enforces a unique MongoDB index, hashes passwords with scrypt, and protects the
form with same-origin and CSRF checks. Re-registering an email uses the same
generic completion page and never replaces its password.

The registration flow does not verify email ownership or recover forgotten
passwords. Add both before enabling public signups.

## What happens during authorization

1. `GET /demo/start` generates random state, nonce, a PKCE verifier, and a
   browser-binding cookie. They are stored in `demo_oauth_requests` for ten minutes.
2. `GET /auth/authorize` opens the package's hosted login and consent pages.
3. The application verifies the password hash. The IdP stores a browser session,
   then returns a short-lived authorization code after consent.
4. `GET /callback` checks state against the stored request and browser cookie, then
   atomically consumes it and exchanges the code using the stored verifier.
5. The OIDC client verifies the ID token's signature through JWKS, checks issuer,
   audience, expiry, and nonce, then stores the access token and verified subject
   in `demo_client_sessions` behind an HTTP-only cookie.
6. `/demo/profile` calls UserInfo and `/api/profile` with the access token, requires
   UserInfo `sub` to match the verified ID-token subject, and renders only claims
   and protected resource data.

The client and resource server share a backend here for convenience. The client
validates state, nonce, issuer, audience, signature, and PKCE just as it would with
a separate provider.

The client's access token must remain retrievable to call the APIs, so
`demo_client_sessions` contains usable credentials and the verified subject;
restrict database access accordingly. The ID token is verified and discarded.
The IdP's own collections contain token hashes. Tokens, passwords, codes, signing
keys, and callback URLs are not logged or rendered by the example.

Login submissions are limited to ten attempts and registration submissions to
five attempts per source and normalized email in each ten-minute window. The
counters live in MongoDB, so the limit is shared by multiple application replicas.
Set `TRUST_PROXY=1` only when the application is behind exactly one trusted proxy
that replaces forwarded client-address headers.

## Verify persistence

After authorizing in the browser, restart only the application:

```powershell
docker compose -p zero-auth-idp-example -f examples/express-idp/docker-compose.yml restart app
```

Revisit `/api/session` and `/demo/profile` in that same browser. Both still work
while their sessions/tokens are valid. Restarting also preserves an authorization
request that is waiting for its callback. Keep `OIDC_PRIVATE_KEY_BASE64` and
`OIDC_KEY_ID` unchanged across restarts so clients can continue using cached JWKS.

**Revoke Demo app access** invalidates the access token and deletes the client
session. **End browser session** logs out of the IdP but does not revoke existing
OAuth access; these are separate lifecycles. Both actions require a matching
browser `Origin`; login and consent also use hidden CSRF tokens.

## Repeatable end-to-end test

With MongoDB running and both packages built:

```powershell
cd examples/express-idp
npm run typecheck
npm test
```

The test compiles the application, creates a unique disposable database, and
starts the built JavaScript on an unused port. It checks registration, unique
normalized emails, password preservation, login throttling, wrong credentials,
CSRF, OIDC discovery, stable JWKS, ID-token verification, UserInfo subject
binding, state/nonce handling, callback replay, denial, revocation, logout,
password hashing, and two actual process restarts. It drops only its test database
and stops its own processes afterward. No tokens or private keys appear in its
output.

The adapter also verifies actual MongoDB TTL deletion. That test waits up to
90 seconds for MongoDB's background cleanup pass:

```powershell
# From the repository root:
$env:MONGODB_URI = "mongodb://127.0.0.1:27017"
npm run test:integration --workspace @0-auth/zero-auth-idp-mongodb
```

CI runs the adapter's MongoDB tests, this example's end-to-end test, and a smoke
test against the standalone container image.

## Curl smoke checks

```powershell
curl.exe -fsS http://localhost:3001/health
curl.exe -fsS http://localhost:3001/auth/.well-known/oauth-authorization-server
curl.exe -fsS http://localhost:3001/auth/.well-known/openid-configuration
curl.exe -fsS http://localhost:3001/auth/.well-known/jwks.json
curl.exe -i http://localhost:3001/api/profile
```

The health endpoint pings MongoDB before returning ready. The first four checks
return 200; the protected route returns 401 without a token.
Use `npm test` for the automated hosted-form/cookie flow, or the browser for
the complete interactive flow. Manual curl form submissions must include
`Origin: http://localhost:3001`, a cookie jar, and current hidden form fields.

## Deploy the container

Build from the example directory:

```powershell
docker build -t zero-auth-idp-example examples/express-idp
docker run --rm --env-file examples/express-idp/.env.production -p 3001:3001 zero-auth-idp-example
```

Configure the hosting platform with an external MongoDB connection and these
production values:

```dotenv
NODE_ENV=production
PORT=3001
PUBLIC_ORIGIN=https://idp.example.com
MONGODB_URI=mongodb+srv://...
MONGODB_DATABASE=zero_auth_idp_example
DEMO_PASSWORD=replace-with-a-long-random-secret
OIDC_PRIVATE_KEY_BASE64=base64-encoded-pkcs8-rsa-private-key
OIDC_KEY_ID=production-key-2026-01
```

Do not commit `.env.production`. The container listens on HTTP internally; the
hosting platform terminates TLS and routes the public HTTPS origin to it. Server
to-server token, revocation, and protected-resource calls stay inside the
container rather than routing back through the public hostname.

## Deployment boundary

Compose is intentionally a localhost development setup with an isolated MongoDB
network and persistent volume. Public deployment also needs HTTPS, database
authentication and TLS, verified email delivery, and password recovery. Use an
HTTPS `PUBLIC_ORIGIN` with `NODE_ENV=production`; cookies become Secure. Refresh
tokens and administration are outside this example.
