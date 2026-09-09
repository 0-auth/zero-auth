import {
  createHash,
  createPrivateKey,
  randomBytes,
  randomUUID,
  scrypt,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import express, { type Request, type RequestHandler } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { MongoClient, MongoServerError } from "mongodb";
import { createIdentityProvider, type IdentityProviderUi } from "@0-auth/zero-auth-idp";
import { createMongoOAuthStorage } from "@0-auth/zero-auth-idp-mongodb";

const port = Number(process.env["PORT"] ?? 3001);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid PORT");
const base = process.env["PUBLIC_ORIGIN"] ?? `http://localhost:${port}`;
const origin = new URL(base);
if (origin.origin !== base || !["http:", "https:"].includes(origin.protocol)) {
  throw new Error("PUBLIC_ORIGIN must be an HTTP(S) origin without a trailing slash");
}
if (process.env["NODE_ENV"] === "production" && origin.protocol !== "https:") {
  throw new Error("Use an HTTPS PUBLIC_ORIGIN in production");
}
const trustProxy = process.env["TRUST_PROXY"] ?? "0";
if (!new Set(["0", "1"]).has(trustProxy)) throw new Error("TRUST_PROXY must be 0 or 1");
const password = process.env["DEMO_PASSWORD"];
if (!password || password.length < 12)
  throw new Error("Set DEMO_PASSWORD to at least 12 characters");
const oidcPrivateKeyBase64 = process.env["OIDC_PRIVATE_KEY_BASE64"];
if (!oidcPrivateKeyBase64) throw new Error("Set OIDC_PRIVATE_KEY_BASE64 to a PKCS8 RSA key");
let oidcSigningKey;
try {
  oidcSigningKey = createPrivateKey(Buffer.from(oidcPrivateKeyBase64, "base64"));
} catch {
  throw new Error("OIDC_PRIVATE_KEY_BASE64 must contain a base64-encoded PKCS8 RSA key");
}
const mongo = new MongoClient(process.env["MONGODB_URI"] ?? "mongodb://127.0.0.1:27017", {
  serverSelectionTimeoutMS: 5000,
});
await mongo.connect();
const db = mongo.db(process.env["MONGODB_DATABASE"] ?? "zero_auth_idp_example");
const storage = createMongoOAuthStorage(db);
await storage.ensureIndexes();

// Application-owned user collection; never write users into adapter collections.
const users = db.collection<{ _id: string; email: string; salt: string; passwordHash: string }>(
  "demo_users"
);
await users.createIndex({ email: 1 }, { unique: true });
const deriveKey = promisify(scrypt);
async function passwordFields(value: string) {
  const salt = randomBytes(16).toString("hex");
  const key = (await deriveKey(value, salt, 64)) as Buffer;
  return { salt, passwordHash: key.toString("hex") };
}
const isDuplicateEmail = (error: unknown) =>
  error instanceof MongoServerError && error.code === 11000;
const email = "user@example.com";
if (!(await users.findOne({ email }))) {
  try {
    await users.insertOne({ _id: "demo-user", email, ...(await passwordFields(password)) });
  } catch (error) {
    if (!isDuplicateEmail(error)) throw error;
  }
}

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const random = () => randomBytes(32).toString("base64url");
const normalizeEmail = (value: string) => value.trim().toLowerCase();
// ponytail: shape validation only; verified delivery becomes authoritative with email verification.
const isValidEmail = (value: string) =>
  value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const internalBase = `http://127.0.0.1:${port}`;
const oidcJwks = createRemoteJWKSet(new URL(`${internalBase}/auth/.well-known/jwks.json`));
const idpCookieName = "idp_session";
const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!
  );
const appPage = (title: string, content: string) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)} · Zero Auth</title>
    <link rel="stylesheet" href="/app.css">
  </head>
  <body>
    <main class="shell">
      <a class="brand" href="/" aria-label="Zero Auth demo home"><span>0</span> Zero Auth</a>
      ${content}
    </main>
  </body>
</html>`;
function sendStatusPage(
  response: express.Response,
  status: number,
  title: string,
  eyebrow: string,
  heading: string,
  message: string,
  actionHref: string,
  actionLabel: string
) {
  response
    .status(status)
    .type("html")
    .send(
      appPage(
        title,
        `<section class="card"><p class="eyebrow">${escapeHtml(eyebrow)}</p><h1>${escapeHtml(heading)}</h1><p class="lede">${escapeHtml(message)}</p><div class="actions"><a class="button" href="${escapeHtml(actionHref)}">${escapeHtml(actionLabel)}</a></div></section>`
      )
    );
}
// Hosted pages stay deliberately semantic because the package's CSP blocks page-supplied styles.
const hostedPage = (title: string, content: string) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)} · Zero Auth Identity</title>
  </head>
  <body>
    <main>
      <p><strong>Zero Auth Identity</strong></p>
      ${content}
    </main>
  </body>
</html>`;
const cookieOptions = {
  httpOnly: true,
  secure: origin.protocol === "https:",
  sameSite: "lax" as const,
  path: "/",
};
function cookie(req: Request, name: string): string {
  return (
    req.headers.cookie
      ?.split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${name}=`))
      ?.slice(name.length + 1) ?? ""
  );
}
function sendRegistrationForm(
  response: express.Response,
  email = "",
  error?: string,
  status = 200
) {
  const csrfToken = random();
  response.cookie("register_csrf", csrfToken, { ...cookieOptions, maxAge: 600_000 });
  response
    .status(status)
    .type("html")
    .send(
      appPage(
        "Create account",
        `<section class="card"><p class="eyebrow">Zero Auth Identity</p><h1>Create your account.</h1><p class="lede">Register an email and password, then continue through the OpenID Connect sign-in flow.</p>${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}<form class="registration" method="post" action="/register"><input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}"><label>Email<input type="email" name="email" value="${escapeHtml(email)}" autocomplete="email" maxlength="254" required></label><label>Password<input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="1024" required></label><label>Confirm password<input type="password" name="confirm_password" autocomplete="new-password" minlength="12" maxlength="1024" required></label><button type="submit">Create account</button></form><p><a href="/">Return home</a></p></section>`
      )
    );
}
function hasAllowedMutationOrigin(req: Request): boolean {
  if (process.env["NODE_ENV"] === "development") return true;
  const requestOrigin = req.get("origin");
  if (requestOrigin === base || (!requestOrigin && req.get("sec-fetch-site") === "same-origin")) {
    return true;
  }
  if (process.env["NODE_ENV"] === "production" || !requestOrigin) return false;
  try {
    const candidate = new URL(requestOrigin);
    const loopback = new Set(["localhost", "127.0.0.1", "[::1]"]);
    return (
      loopback.has(origin.hostname) &&
      loopback.has(candidate.hostname) &&
      candidate.protocol === origin.protocol &&
      candidate.port === origin.port
    );
  } catch {
    return false;
  }
}
const hostedUi: IdentityProviderUi = {
  renderLogin: (context) =>
    hostedPage(
      "Sign in",
      `<p>Continue to <strong>Demo app</strong>.</p>
      <h1>Sign in</h1>
      ${context.error ? `<p role="alert">${escapeHtml(context.error)}</p>` : ""}
      <form method="post" action="${escapeHtml(context.action)}">
        <input type="hidden" name="transaction" value="${escapeHtml(context.transactionId)}">
        <input type="hidden" name="csrf_token" value="${escapeHtml(context.csrfToken)}">
        <p><label>Email<br><input type="email" name="email" value="${escapeHtml(context.email ?? "")}" autocomplete="email" required></label></p>
        <p><label>Password<br><input type="password" name="password" autocomplete="current-password" required></label></p>
        <button type="submit">Continue</button>
      </form>`
    ),
  renderConsent: (context) =>
    hostedPage(
      "Authorize application",
      `<p>Signed in to <strong>Zero Auth Identity</strong>.</p>
      <h1>Allow ${escapeHtml(context.clientName)}?</h1>
      <p>The application is requesting permission to:</p>
      <ul>${context.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("")}</ul>
      <form method="post" action="${escapeHtml(context.action)}">
        <input type="hidden" name="transaction" value="${escapeHtml(context.transactionId)}">
        <input type="hidden" name="csrf_token" value="${escapeHtml(context.csrfToken)}">
        <button type="submit" name="decision" value="deny">Deny</button>
        <button type="submit" name="decision" value="allow">Allow Demo app</button>
      </form>`
    ),
  renderError: (context) =>
    hostedPage(
      "Authentication error",
      `<h1>We could not continue</h1><p role="alert">${escapeHtml(context.message)}</p><p><a href="/">Return to Demo app</a></p>`
    ),
};
const idp = createIdentityProvider({
  issuer: `${base}/auth`,
  storage,
  oidc: {
    signingKey: oidcSigningKey,
    keyId: process.env["OIDC_KEY_ID"] ?? "demo-key-1",
  },
  cookie: { ...cookieOptions, name: idpCookieName },
  ui: hostedUi,
  clients: [
    {
      clientId: "demo-app",
      name: "Demo app",
      clientType: "public",
      redirectUris: [`${base}/callback`],
      allowedScopes: ["openid", "profile", "email"],
    },
  ],
  authenticateUser: async (credentials) => {
    const loginEmail = normalizeEmail(credentials.email);
    if (!isValidEmail(loginEmail) || credentials.password.length > 1024) return null;
    const user = await users.findOne({ email: loginEmail });
    if (!user) return null;
    const key = (await deriveKey(credentials.password, user.salt, 64)) as Buffer;
    const storedKey = Buffer.from(user.passwordHash, "hex");
    return storedKey.length === key.length && timingSafeEqual(key, storedKey)
      ? { id: user._id, email: user.email }
      : null;
  },
});

const pending = db.collection<{
  _id: string;
  browserHash: string;
  verifier: string;
  nonce: string;
  expiresAt: Date;
}>("demo_oauth_requests");
// This client needs its access token to call the API. Treat this collection as credential storage.
const sessions = db.collection<{
  _id: string;
  accessToken: string;
  subject: string;
  expiresAt: Date;
}>("demo_client_sessions");
const attempts = db.collection<{ _id: string; count: number; expiresAt: Date }>(
  "demo_request_limits"
);
await Promise.all([
  pending.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
  sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
  attempts.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
]);
// ponytail: fixed windows can allow a boundary burst; use a rolling limiter if that becomes material.
const attemptWindowMs = 10 * 60_000;
async function consumeAttempt(kind: string, source: string, subject: string, limit: number) {
  const bucket = Math.floor(Date.now() / attemptWindowMs);
  const attempt = await attempts.findOneAndUpdate(
    { _id: hash(`${kind}\0${source}\0${subject}\0${bucket}`) },
    {
      $inc: { count: 1 },
      $setOnInsert: { expiresAt: new Date((bucket + 2) * attemptWindowMs) },
    },
    { upsert: true, returnDocument: "after" }
  );
  return {
    limited: (attempt?.count ?? 0) > limit,
    retryAfter: Math.max(1, Math.ceil(((bucket + 1) * attemptWindowMs - Date.now()) / 1000)),
  };
}

const app = express();
app.disable("x-powered-by");
if (trustProxy === "1") app.set("trust proxy", 1);
app.use((_req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  });
  next();
});
const route =
  (handler: (req: Request, res: express.Response) => Promise<void>): RequestHandler =>
  (req, res, next) => {
    void handler(req, res).catch(next);
  };
// Browser mutations require an explicit matching Origin, including registration and hosted forms.
app.use((req, res, next) => {
  if (
    req.method === "POST" &&
    [
      "/register",
      "/auth/login",
      "/auth/consent",
      "/auth/logout",
      "/demo/revoke",
      "/demo/logout",
    ].includes(req.path.toLowerCase().replace(/\/+$/, "")) &&
    !hasAllowedMutationOrigin(req)
  ) {
    sendStatusPage(
      res,
      403,
      "Open the canonical demo URL",
      "Request blocked",
      "This form came from a different browser origin.",
      `Open ${base} and try the action again.`,
      base,
      "Open Demo app"
    );
    return;
  }
  next();
});
app.post(
  "/auth/login",
  express.urlencoded({ extended: false, limit: "16kb" }),
  (req, res, next) => {
    void (async () => {
      const loginEmail = typeof req.body?.email === "string" ? normalizeEmail(req.body.email) : "";
      const source = req.ip ?? req.socket.remoteAddress ?? "unknown";
      const result = await consumeAttempt("login", source, loginEmail, 10);
      if (result.limited) {
        res.set("Retry-After", String(result.retryAfter));
        sendStatusPage(
          res,
          429,
          "Try again later",
          "Identity provider",
          "Too many sign-in attempts",
          "Wait a few minutes, then start the sign-in flow again.",
          "/",
          "Return to Demo app"
        );
        return;
      }
      next();
    })().catch(next);
  }
);
app.use("/auth", idp.router());
app.get(
  "/health",
  route(async (_req, res) => {
    try {
      await db.command({ ping: 1 });
      res.json({ ready: true });
    } catch {
      res.status(503).json({ ready: false });
    }
  })
);
app.get("/app.css", (_req, res) => {
  res.type("css").send(`
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #17211b; background: #f3f1e9; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(circle at top right, #dbead9, transparent 34rem), #f3f1e9; }
    .shell { width: min(46rem, calc(100% - 2rem)); margin: 0 auto; padding: 2rem 0 5rem; }
    .brand { display: inline-flex; align-items: center; gap: .6rem; color: inherit; font-weight: 750; text-decoration: none; letter-spacing: -.02em; }
    .brand span { display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: 50%; color: white; background: #17211b; }
    .card { margin-top: 4rem; padding: clamp(1.5rem, 5vw, 3.5rem); border: 1px solid #cdd4c8; border-radius: 1.5rem; background: rgba(255,255,255,.78); box-shadow: 0 1.5rem 4rem rgba(38,55,43,.09); }
    .eyebrow { margin: 0 0 1rem; color: #3f6a4b; font-size: .78rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
    h1 { max-width: 15ch; margin: 0; font-size: clamp(2.2rem, 8vw, 4.5rem); line-height: .98; letter-spacing: -.065em; }
    .lede { max-width: 36rem; margin: 1.5rem 0 0; color: #4c5c51; font-size: 1.1rem; line-height: 1.65; }
    .actions { display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 2rem; }
    .button, button { display: inline-flex; justify-content: center; border: 1px solid #17211b; border-radius: 999px; padding: .75rem 1rem; color: white; background: #17211b; font: inherit; font-weight: 700; text-decoration: none; cursor: pointer; }
    .button.secondary, button.secondary { color: #17211b; background: transparent; }
    .steps { display: grid; gap: 1rem; margin: 2.5rem 0 0; padding: 0; list-style: none; counter-reset: step; }
    .steps li { display: grid; grid-template-columns: 2rem 1fr; gap: .75rem; align-items: start; color: #4c5c51; line-height: 1.5; }
    .steps li::before { counter-increment: step; content: counter(step); display: grid; place-items: center; width: 2rem; height: 2rem; border: 1px solid #aebaac; border-radius: 50%; color: #17211b; font-weight: 800; }
    .result { margin-top: 2rem; padding: 1.25rem; border-radius: 1rem; background: #e7efe4; }
    .result dt { color: #57705d; font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .result dd { margin: .25rem 0 1rem; font-size: 1.1rem; }
    .registration { display: grid; gap: 1rem; margin-top: 2rem; }
    .registration label { display: grid; gap: .4rem; font-weight: 700; }
    .registration input { width: 100%; border: 1px solid #aebaac; border-radius: .7rem; padding: .75rem; color: inherit; background: white; font: inherit; }
    .registration button { justify-self: start; }
    form { display: inline; }
    details { margin-top: 2rem; color: #4c5c51; }
    summary { cursor: pointer; font-weight: 700; }
    a:focus-visible, button:focus-visible { outline: 3px solid #e17440; outline-offset: 3px; }
    @media (max-width: 34rem) { .card { margin-top: 2rem; } .actions > * { width: 100%; } .actions form button { width: 100%; } }
  `);
});
app.get("/register", (_req, res) => sendRegistrationForm(res));
app.post(
  "/register",
  express.urlencoded({ extended: false, limit: "16kb" }),
  route(async (req, res) => {
    const submittedCsrf = typeof req.body?.csrf_token === "string" ? req.body.csrf_token : "";
    const expectedCsrf = cookie(req, "register_csrf");
    if (
      !submittedCsrf ||
      !expectedCsrf ||
      !timingSafeEqual(
        Buffer.from(hash(submittedCsrf), "hex"),
        Buffer.from(hash(expectedCsrf), "hex")
      )
    ) {
      sendStatusPage(
        res,
        400,
        "Registration expired",
        "Zero Auth Identity",
        "This registration cannot continue.",
        "Open a fresh registration form and try again.",
        "/register",
        "Start again"
      );
      return;
    }
    res.clearCookie("register_csrf", cookieOptions);
    const registrationEmail =
      typeof req.body?.email === "string" ? normalizeEmail(req.body.email) : "";
    const registrationPassword = typeof req.body?.password === "string" ? req.body.password : "";
    const confirmation =
      typeof req.body?.confirm_password === "string" ? req.body.confirm_password : "";
    const source = req.ip ?? req.socket.remoteAddress ?? "unknown";
    const result = await consumeAttempt("register", source, registrationEmail, 5);
    if (result.limited) {
      res.set("Retry-After", String(result.retryAfter));
      sendStatusPage(
        res,
        429,
        "Try again later",
        "Zero Auth Identity",
        "Too many registration attempts",
        "Wait a few minutes, then open a fresh registration form.",
        "/register",
        "Return to registration"
      );
      return;
    }
    if (!isValidEmail(registrationEmail)) {
      sendRegistrationForm(res, registrationEmail, "Enter a valid email address.", 400);
      return;
    }
    if (registrationPassword.length < 12 || registrationPassword.length > 1024) {
      sendRegistrationForm(
        res,
        registrationEmail,
        "Use a password between 12 and 1024 characters.",
        400
      );
      return;
    }
    if (registrationPassword !== confirmation) {
      sendRegistrationForm(res, registrationEmail, "The passwords do not match.", 400);
      return;
    }
    try {
      await users.insertOne({
        _id: randomUUID(),
        email: registrationEmail,
        ...(await passwordFields(registrationPassword)),
      });
    } catch (error) {
      if (!isDuplicateEmail(error)) throw error;
    }
    res.redirect(303, "/register/complete");
  })
);
app.get("/register/complete", (_req, res) => {
  sendStatusPage(
    res,
    200,
    "Account ready",
    "Zero Auth Identity",
    "Continue to sign in.",
    "If the email was already registered, its existing password was kept.",
    "/demo/start",
    "Continue to identity provider"
  );
});
app.get("/", (_req, res) => {
  res.type("html").send(
    appPage(
      "OIDC end-user flow",
      `<section class="card">
        <p class="eyebrow">Runnable OpenID Connect example</p>
        <h1>See a sign-in flow end to end.</h1>
        <p class="lede">Create an account or use <strong>user@example.com</strong>, then Demo app will send you to Zero Auth Identity and return after verifying the signed identity response.</p>
        <div class="actions"><a class="button" href="/demo/start">Continue to identity provider</a><a class="button secondary" href="/register">Create account</a><a class="button secondary" href="/demo/profile">View authorized profile</a></div>
        <ol class="steps"><li>Demo app creates state, nonce, a browser binding, and a PKCE challenge.</li><li>The identity provider authenticates you and asks for consent.</li><li>Demo app verifies the ID token through JWKS, then calls UserInfo and the protected API.</li></ol>
        <details><summary>Existing session controls</summary><div class="actions"><form action="/demo/revoke" method="post"><button class="secondary" type="submit">Revoke app access</button></form><form action="/demo/logout" method="post"><button class="secondary" type="submit">End identity session</button></form></div></details>
      </section>`
    )
  );
});
app.get(
  "/demo/start",
  route(async (_req, res) => {
    const state = random();
    const verifier = random();
    const browser = random();
    const nonce = random();
    await pending.insertOne({
      _id: hash(state),
      browserHash: hash(browser),
      verifier,
      nonce,
      expiresAt: new Date(Date.now() + 600_000),
    });
    res.cookie("demo_flow", browser, { ...cookieOptions, maxAge: 600_000 });
    const url = new URL(`${base}/auth/authorize`);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: `${base}/callback`,
      scope: "openid profile email",
      state,
      nonce,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
    }).toString();
    res.redirect(url.toString());
  })
);
app.get(
  "/callback",
  route(async (req, res) => {
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const browser = cookie(req, "demo_flow");
    if (!state || !browser) {
      sendStatusPage(
        res,
        400,
        "Authorization expired",
        "Demo app",
        "This authorization request cannot continue.",
        "The request expired or no longer matches this browser. Start again to create a fresh, protected request.",
        "/demo/start",
        "Start again"
      );
      return;
    }
    const flow = await pending.findOneAndDelete({
      _id: hash(state),
      browserHash: hash(browser),
      expiresAt: { $gt: new Date() },
    });
    if (!flow) {
      sendStatusPage(
        res,
        400,
        "Authorization expired",
        "Demo app",
        "This authorization request cannot continue.",
        "The request expired, was already used, or no longer matches this browser.",
        "/demo/start",
        "Start again"
      );
      return;
    }
    res.clearCookie("demo_flow", cookieOptions);
    if (req.query.error) {
      sendStatusPage(
        res,
        400,
        "Access denied",
        "Demo app",
        "No access was granted.",
        "You denied the request. Demo app did not receive an access token.",
        "/",
        "Return home"
      );
      return;
    }
    if (typeof req.query.code !== "string") {
      sendStatusPage(
        res,
        400,
        "Missing authorization code",
        "Demo app",
        "The identity provider response was incomplete.",
        "Start again to create a fresh authorization request.",
        "/demo/start",
        "Start again"
      );
      return;
    }
    const response = await fetch(`${internalBase}/auth/token`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(5000),
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "demo-app",
        code: req.query.code,
        redirect_uri: `${base}/callback`,
        code_verifier: flow.verifier,
      }),
    });
    const token = (await response.json()) as {
      access_token?: string;
      expires_in?: number;
      id_token?: string;
    };
    if (
      !response.ok ||
      typeof token.access_token !== "string" ||
      typeof token.id_token !== "string" ||
      !Number.isFinite(token.expires_in) ||
      token.expires_in! <= 0
    ) {
      sendStatusPage(
        res,
        502,
        "Authorization unavailable",
        "Demo app",
        "We could not finish authorization.",
        "Try the flow again. If the problem continues, check the identity provider service.",
        "/demo/start",
        "Try again"
      );
      return;
    }
    let subject: string;
    try {
      const { payload } = await jwtVerify(token.id_token, oidcJwks, {
        issuer: `${base}/auth`,
        audience: "demo-app",
        algorithms: ["RS256"],
        typ: "JWT",
        requiredClaims: ["sub", "iat", "exp", "nonce"],
      });
      if (typeof payload.sub !== "string" || payload.nonce !== flow.nonce) {
        throw new Error("Invalid OIDC subject or nonce");
      }
      subject = payload.sub;
    } catch {
      sendStatusPage(
        res,
        502,
        "Identity verification failed",
        "Demo app",
        "We could not verify the identity response.",
        "Start again to create a fresh OpenID Connect request.",
        "/demo/start",
        "Try again"
      );
      return;
    }
    const session = random();
    await sessions.insertOne({
      _id: hash(session),
      accessToken: token.access_token,
      subject,
      expiresAt: new Date(Date.now() + token.expires_in! * 1000),
    });
    res.cookie("demo_session", session, { ...cookieOptions, maxAge: token.expires_in! * 1000 });
    res.redirect("/demo/profile");
  })
);
app.get(
  "/demo/profile",
  route(async (req, res) => {
    const session = await sessions.findOne({
      _id: hash(cookie(req, "demo_session")),
      expiresAt: { $gt: new Date() },
    });
    if (!session) {
      sendStatusPage(
        res,
        401,
        "Authorization required",
        "Demo app",
        "Authorize Demo app first.",
        "No active client session was found in this browser.",
        "/demo/start",
        "Continue to identity provider"
      );
      return;
    }
    const [response, userInfoResponse] = await Promise.all([
      fetch(`${internalBase}/api/profile`, {
        headers: { Authorization: `Bearer ${session.accessToken}` },
        redirect: "error",
        signal: AbortSignal.timeout(5000),
      }),
      fetch(`${internalBase}/auth/userinfo`, {
        headers: { Authorization: `Bearer ${session.accessToken}` },
        redirect: "error",
        signal: AbortSignal.timeout(5000),
      }),
    ]);
    const [profile, identity] = await Promise.all([
      response.json() as Promise<{ userId?: string; scopes?: string[] }>,
      userInfoResponse.json() as Promise<{ sub?: string; email?: string }>,
    ]);
    if (
      !response.ok ||
      !userInfoResponse.ok ||
      typeof profile.userId !== "string" ||
      !Array.isArray(profile.scopes) ||
      typeof identity.sub !== "string" ||
      identity.sub !== session.subject
    ) {
      sendStatusPage(
        res,
        502,
        "Profile unavailable",
        "Demo app",
        "The identity provider or protected API rejected this session.",
        "Authorize again to obtain fresh access.",
        "/demo/start",
        "Authorize again"
      );
      return;
    }
    res
      .type("html")
      .send(
        appPage(
          "Verified identity",
          `<section class="card"><p class="eyebrow">OpenID Connect complete</p><h1>Demo app verified your identity.</h1><p class="lede">The signed ID token was verified through the provider's JWKS. Tokens stayed on the server; this page contains only verified claims and the protected resource response.</p><dl class="result"><dt>OIDC subject</dt><dd>${escapeHtml(identity.sub)}</dd><dt>Email from UserInfo</dt><dd>${escapeHtml(identity.email ?? "Not provided")}</dd><dt>Protected API user</dt><dd>${escapeHtml(profile.userId)}</dd><dt>Granted scopes</dt><dd>${profile.scopes.map(escapeHtml).join(", ")}</dd></dl><div class="actions"><a class="button secondary" href="/">Return home</a><form action="/demo/revoke" method="post"><button type="submit">Revoke app access</button></form><form action="/demo/logout" method="post"><button class="secondary" type="submit">End identity session</button></form></div></section>`
        )
      );
  })
);
app.post(
  "/demo/revoke",
  route(async (req, res) => {
    const key = hash(cookie(req, "demo_session"));
    const session = await sessions.findOne({ _id: key });
    if (session) {
      const response = await fetch(`${internalBase}/auth/revoke`, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(5000),
        body: new URLSearchParams({ client_id: "demo-app", token: session.accessToken }),
      });
      if (!response.ok) {
        sendStatusPage(
          res,
          502,
          "Revocation unavailable",
          "Demo app",
          "Access could not be revoked.",
          "Try again before closing this browser session.",
          "/demo/profile",
          "Try again"
        );
        return;
      }
      await sessions.deleteOne({ _id: key });
    }
    res.clearCookie("demo_session", cookieOptions);
    res.redirect("/");
  })
);
app.post(
  "/demo/logout",
  route(async (req, res) => {
    const response = await fetch(`${internalBase}/auth/logout`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(5000),
      headers: { Cookie: req.headers.cookie ?? "", Origin: base },
    });
    if (!response.ok) {
      sendStatusPage(
        res,
        502,
        "Sign out unavailable",
        "Identity provider",
        "The identity session could not be ended.",
        "Try again before leaving the demo.",
        "/demo/profile",
        "Return to profile"
      );
      return;
    }
    res.clearCookie(idpCookieName, cookieOptions);
    res.redirect("/");
  })
);
app.get("/api/session", idp.requireSession(), (req, res) => {
  res.json({ userId: req.idpUser?.id, email: req.idpUser?.email });
});
app.get("/api/profile", idp.authenticateBearer(["profile"]), (req, res) => {
  res.json({ userId: req.oauth?.user.id, scopes: req.oauth?.scopes });
});
app.use((_error: unknown, req: Request, res: express.Response, next: express.NextFunction) => {
  if (res.headersSent) {
    next(_error);
    return;
  }
  if (req.path.startsWith("/api/") || req.path === "/health") {
    res.status(500).json({ error: "request_failed" });
    return;
  }
  sendStatusPage(
    res,
    500,
    "Request failed",
    "Zero Auth demo",
    "Something went wrong.",
    "Try the flow again. No credentials or tokens were displayed.",
    "/",
    "Return home"
  );
});
const server = app.listen(port, "0.0.0.0", () => console.log(`OIDC example ready at ${base}`));
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    server.close(() => {
      void mongo.close().then(() => process.exit(0));
    });
    server.closeIdleConnections();
  });
}
