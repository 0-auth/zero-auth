# Express OAuth example with MongoDB

> [!NOTE]
> The example now requires MongoDB and `DEMO_PASSWORD` (at least 12 characters).
> The previous hard-coded password is removed. Start at `/`; the callback now
> validates state and exchanges the code automatically. This is a local example,
> not a production identity service.

One Express backend demonstrates three roles: an authorization server with hosted
login/consent, an OAuth client, and a protected resource API. MongoDB persists each
role's state so the application can restart without signing everyone out.

## Run with Docker Compose

From the repository root, using PowerShell:

```powershell
$env:DEMO_PASSWORD = "choose-a-long-local-demo-password"
docker compose -p zero-auth-idp-example -f examples/express-idp/docker-compose.yml up --build -d --wait
```

In Bash, use `export DEMO_PASSWORD='choose-a-long-local-demo-password'` before
the same Compose command. Alternatively, copy `.env.example` to `.env` in
this example directory and choose a password. Never commit that file.

Open [http://localhost:3001](http://localhost:3001), click **Sign in and authorize
Demo app**, sign in as `user@example.com` with your configured password, and
approve consent. The result is:

```json
{ "userId": "demo-user", "scopes": ["profile"] }
```

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
npm ci
npm run build --workspace @0-auth/zero-auth-idp
npm run build --workspace @0-auth/zero-auth-idp-mongodb
cd examples/express-idp
npm ci
$env:MONGODB_URI = "mongodb://127.0.0.1:27017"
$env:MONGODB_DATABASE = "zero_auth_idp_example"
$env:DEMO_PASSWORD = "choose-a-long-local-demo-password"
npm start
```

The local adapter is not published yet; this example uses repository `file:`
dependencies. Build both packages before starting it. For Node execution, export
environment variables as shown; `npm start` does not automatically load `.env`.

| Variable           | Default / requirement                                               |
| ------------------ | ------------------------------------------------------------------- |
| `DEMO_PASSWORD`    | Required, at least 12 characters; used only when seeding a new user |
| `MONGODB_URI`      | `mongodb://127.0.0.1:27017`                                         |
| `MONGODB_DATABASE` | `zero_auth_idp_example`                                             |
| `PORT`             | `3001`                                                              |
| `PUBLIC_ORIGIN`    | `http://localhost:<PORT>`, without a trailing slash                 |

Seeding is idempotent. The password is stored as a salted scrypt hash in the
application's `demo_users` collection. Changing `DEMO_PASSWORD` after the first
run does not overwrite an existing password. The IdP adapter never manages users.

## What happens during authorization

1. `GET /demo/start` generates random state, a PKCE verifier, and a browser-binding
   cookie. The state/verifier are stored in `demo_oauth_requests` for ten minutes.
2. `GET /auth/authorize` opens the package's hosted login and consent pages.
3. The application verifies the password hash. The IdP stores a browser session,
   then returns a short-lived authorization code after consent.
4. `GET /callback` checks state against the stored request and the browser cookie.
   It atomically consumes the request, then exchanges the code using the stored
   verifier. Missing, changed, expired, or replayed state is rejected.
5. The OAuth client stores its access token in `demo_client_sessions`, sets an
   HTTP-only cookie, and redirects to `/demo/profile` to remove callback parameters
   from the current URL.
6. `/demo/profile` sends that token to `/api/profile` as a Bearer credential.
   The API validates the token and requires the `profile` scope.

The client and resource server share a backend here for convenience. The client
validates state and uses PKCE just as it would with a separate server.

The client's token must remain retrievable to call the API, so
`demo_client_sessions` contains usable credentials; restrict database access
accordingly. The IdP's own collections contain token hashes. Tokens, passwords,
codes, and callback URLs are not logged or rendered by the example.

## Verify persistence

After authorizing in the browser, restart only the application:

```powershell
docker compose -p zero-auth-idp-example -f examples/express-idp/docker-compose.yml restart app
```

Revisit `/api/session` and `/demo/profile` in that same browser. Both still work
while their sessions/tokens are valid. Restarting also preserves an authorization
request that is waiting for its callback.

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

The test creates a unique disposable database and starts its own application on
an unused port. It checks wrong credentials, CSRF, state tampering, browser
binding, callback replay, denial, revocation, logout, password hashing, and two
actual process restarts. It drops only its test database and stops its own
processes afterward. No tokens appear in its output.

The adapter also verifies actual MongoDB TTL deletion. That test waits up to
90 seconds for MongoDB's background cleanup pass:

```powershell
# From the repository root:
$env:MONGODB_URI = "mongodb://127.0.0.1:27017"
npm run test:integration --workspace @0-auth/zero-auth-idp-mongodb
```

CI runs both the adapter's MongoDB tests and this example's end-to-end test.

## Curl smoke checks

```powershell
curl.exe -fsS http://localhost:3001/health
curl.exe -fsS http://localhost:3001/auth/.well-known/oauth-authorization-server
curl.exe -i http://localhost:3001/api/profile
```

The first two return 200; the protected route returns 401 without a token.
Use `npm test` for the automated hosted-form/cookie flow, or the browser for
the complete interactive flow. Manual curl form submissions must include
`Origin: http://localhost:3001`, a cookie jar, and current hidden form fields.

## Deployment boundary

Compose is intentionally a localhost development setup with an isolated MongoDB
network and persistent volume. Public deployment also needs HTTPS, database
authentication, login rate limits, and an account/password recovery policy.
Use an HTTPS `PUBLIC_ORIGIN` with `NODE_ENV=production`; cookies become Secure.
The configured origin must be reachable from the backend for its client API
calls. Registration, OIDC, refresh tokens, and password reset are outside this
example.
