# Express OAuth example with MongoDB

> [!NOTE]
> The example requires MongoDB and `DEMO_PASSWORD` (at least 12 characters).
> It is a deployable OAuth demonstration with one seeded user, not a production
> identity directory or an OpenID Connect provider.

One Express backend demonstrates three roles: an authorization server with hosted
login/consent, an OAuth client, and a protected resource API. MongoDB persists each
role's state so the application can restart without signing everyone out. Its
container installs the published packages and runs without the monorepo.

## Run with Docker Compose

From the repository root, using PowerShell:

```powershell
$env:DEMO_PASSWORD = "choose-a-long-local-demo-password"
docker compose -p zero-auth-idp-example -f examples/express-idp/docker-compose.yml up --build -d --wait
```

In Bash, use `export DEMO_PASSWORD='choose-a-long-local-demo-password'` before
the same Compose command. Alternatively, copy `.env.example` to `.env` in
this example directory and choose a password. Never commit that file.

Open [http://localhost:3001](http://localhost:3001), click **Continue to identity
provider**, sign in as `user@example.com` with your configured password, and
approve consent. Demo app then renders the protected profile response without
displaying the access token.

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
npm run build
npm start
```

For Node execution, export environment variables as shown; `npm start` does not
automatically load `.env`.

| Variable           | Default / requirement                                               |
| ------------------ | ------------------------------------------------------------------- |
| `DEMO_PASSWORD`    | Required, at least 12 characters; used only when seeding a new user |
| `MONGODB_URI`      | `mongodb://127.0.0.1:27017`                                         |
| `MONGODB_DATABASE` | `zero_auth_idp_example`                                             |
| `PORT`             | `3001`                                                              |
| `PUBLIC_ORIGIN`    | `http://localhost:<PORT>`, without a trailing slash                 |
| `TRUST_PROXY`      | `0`; use `1` only behind one trusted proxy hop                      |

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
6. `/demo/profile` sends that token to `/api/profile` as a Bearer credential and
   renders the returned user and scopes. The API validates the token and requires
   the `profile` scope.

The client and resource server share a backend here for convenience. The client
validates state and uses PKCE just as it would with a separate server.

The client's token must remain retrievable to call the API, so
`demo_client_sessions` contains usable credentials; restrict database access
accordingly. The IdP's own collections contain token hashes. Tokens, passwords,
codes, and callback URLs are not logged or rendered by the example.

Login submissions are limited to ten attempts per source and normalized email in
each ten-minute window. The counters live in MongoDB, so the limit is shared by
multiple application replicas. Set `TRUST_PROXY=1` only when the application is
behind exactly one trusted proxy that replaces forwarded client-address headers.

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

The test compiles the application, creates a unique disposable database, and
starts the built JavaScript on an unused port. It checks the browser pages, login
throttling, wrong credentials, CSRF, state tampering, browser binding, callback
replay, denial, revocation, logout, password hashing, and two actual process
restarts. It drops only its test database and stops its own processes afterward.
No tokens appear in its output.

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
curl.exe -i http://localhost:3001/api/profile
```

The health endpoint pings MongoDB before returning ready. The first two checks
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
```

Do not commit `.env.production`. The container listens on HTTP internally; the
hosting platform terminates TLS and routes the public HTTPS origin to it. Server
to-server token, revocation, and protected-resource calls stay inside the
container rather than routing back through the public hostname.

## Deployment boundary

Compose is intentionally a localhost development setup with an isolated MongoDB
network and persistent volume. Public deployment also needs HTTPS, database
authentication and TLS, and an account/password recovery policy. Use an HTTPS
`PUBLIC_ORIGIN` with `NODE_ENV=production`; cookies become Secure. Registration,
OIDC, refresh tokens, password reset, and administration are outside this example.
