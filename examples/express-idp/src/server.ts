import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import express, { type Request, type RequestHandler } from "express";
import { MongoClient } from "mongodb";
import { createIdentityProvider } from "@0-auth/zero-auth-idp";
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
const password = process.env["DEMO_PASSWORD"];
if (!password || password.length < 12)
  throw new Error("Set DEMO_PASSWORD to at least 12 characters");
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
const deriveKey = promisify(scrypt);
const email = "user@example.com";
if (!(await users.findOne({ _id: "demo-user" }))) {
  const salt = randomBytes(16).toString("hex");
  const key = (await deriveKey(password, salt, 64)) as Buffer;
  await users.updateOne(
    { _id: "demo-user" },
    {
      $setOnInsert: {
        email,
        salt,
        passwordHash: key.toString("hex"),
      },
    },
    { upsert: true }
  );
}

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const random = () => randomBytes(32).toString("base64url");
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
const idp = createIdentityProvider({
  issuer: `${base}/auth`,
  storage,
  cookie: cookieOptions,
  clients: [
    {
      clientId: "demo-app",
      name: "Demo app",
      clientType: "public",
      redirectUris: [`${base}/callback`],
      allowedScopes: ["profile"],
    },
  ],
  authenticateUser: async (credentials) => {
    if (credentials.email.length > 254 || credentials.password.length > 1024) return null;
    const user = await users.findOne({ _id: "demo-user" });
    if (!user) return null;
    const key = (await deriveKey(credentials.password, user.salt, 64)) as Buffer;
    return timingSafeEqual(key, Buffer.from(user.passwordHash, "hex")) &&
      credentials.email === user.email
      ? { id: user._id, email: user.email }
      : null;
  },
});

const pending = db.collection<{
  _id: string;
  browserHash: string;
  verifier: string;
  expiresAt: Date;
}>("demo_oauth_requests");
// This client needs its access token to call the API. Treat this collection as credential storage.
const sessions = db.collection<{ _id: string; accessToken: string; expiresAt: Date }>(
  "demo_client_sessions"
);
await Promise.all([
  pending.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
  sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
]);

const app = express();
app.disable("x-powered-by");
app.use((_req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  });
  next();
});
const route =
  (handler: (req: Request, res: express.Response) => Promise<void>): RequestHandler =>
  (req, res, next) => {
    void handler(req, res).catch(next);
  };
// Browser mutations require an explicit matching Origin, including hosted login/consent/logout.
app.use((req, res, next) => {
  if (
    req.method === "POST" &&
    ["/auth/login", "/auth/consent", "/auth/logout", "/demo/revoke"].includes(
      req.path.toLowerCase().replace(/\/+$/, "")
    ) &&
    req.get("origin") !== base
  ) {
    res.status(403).json({ error: "invalid_origin" });
    return;
  }
  next();
});
app.use("/auth", idp.router());
app.get("/health", (_req, res) => {
  res.json({ ready: true });
});
app.get("/", (_req, res) => {
  res.type("html")
    .send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>OAuth MongoDB example</title></head><body><main>
    <h1>OAuth MongoDB example</h1><p>Sign in as user@example.com using the password you configured.</p>
    <p><a href="/demo/start">Sign in and authorize Demo app</a></p>
    <p><a href="/demo/profile">Call the protected API</a> · <a href="/api/session">Check browser session</a></p>
    <form action="/demo/revoke" method="post"><button>Revoke Demo app access</button></form>
    <form action="/auth/logout" method="post"><button>End browser session</button></form>
    </main></body></html>`);
});
app.get(
  "/demo/start",
  route(async (_req, res) => {
    const state = random();
    const verifier = random();
    const browser = random();
    await pending.insertOne({
      _id: hash(state),
      browserHash: hash(browser),
      verifier,
      expiresAt: new Date(Date.now() + 600_000),
    });
    res.cookie("demo_flow", browser, { ...cookieOptions, maxAge: 600_000 });
    const url = new URL(`${base}/auth/authorize`);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: `${base}/callback`,
      scope: "profile",
      state,
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
      res.status(400).json({ error: "invalid_state" });
      return;
    }
    const flow = await pending.findOneAndDelete({
      _id: hash(state),
      browserHash: hash(browser),
      expiresAt: { $gt: new Date() },
    });
    if (!flow) {
      res.status(400).json({ error: "invalid_state" });
      return;
    }
    res.clearCookie("demo_flow", cookieOptions);
    if (req.query.error) {
      res.status(400).json({ error: "authorization_denied" });
      return;
    }
    if (typeof req.query.code !== "string") {
      res.status(400).json({ error: "missing_code" });
      return;
    }
    const response = await fetch(`${base}/auth/token`, {
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
    const token = (await response.json()) as { access_token?: string; expires_in?: number };
    if (
      !response.ok ||
      typeof token.access_token !== "string" ||
      !Number.isFinite(token.expires_in) ||
      token.expires_in! <= 0
    ) {
      res.status(502).json({ error: "token_exchange_failed" });
      return;
    }
    const session = random();
    await sessions.insertOne({
      _id: hash(session),
      accessToken: token.access_token,
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
      res.status(401).json({ error: "sign_in_required" });
      return;
    }
    const response = await fetch(`${base}/api/profile`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    res.status(response.status).json(await response.json());
  })
);
app.post(
  "/demo/revoke",
  route(async (req, res) => {
    const key = hash(cookie(req, "demo_session"));
    const session = await sessions.findOne({ _id: key });
    if (session) {
      const response = await fetch(`${base}/auth/revoke`, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(5000),
        body: new URLSearchParams({ client_id: "demo-app", token: session.accessToken }),
      });
      if (!response.ok) {
        res.status(502).json({ error: "revocation_failed" });
        return;
      }
      await sessions.deleteOne({ _id: key });
    }
    res.clearCookie("demo_session", cookieOptions);
    res.redirect("/");
  })
);
app.get("/api/session", idp.requireSession(), (req, res) => {
  res.json({ userId: req.idpUser?.id, email: req.idpUser?.email });
});
app.get("/api/profile", idp.authenticateBearer(["profile"]), (req, res) => {
  res.json({ userId: req.oauth?.user.id, scopes: req.oauth?.scopes });
});
app.use((_error: unknown, _req: Request, res: express.Response, _next: express.NextFunction) => {
  res.status(500).json({ error: "request_failed" });
});
const server = app.listen(port, "0.0.0.0", () => console.log(`OAuth example ready at ${base}`));
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    server.close(() => {
      void mongo.close().then(() => process.exit(0));
    });
    server.closeIdleConnections();
  });
}
