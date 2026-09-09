import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { MongoClient } from "mongodb";

// An owned database and child process make this safe beside other local applications.
const uri = process.env.MONGODB_URI ?? "mongodb://127.0.0.1:27017";
const database = `zero_auth_example_test_${randomUUID().replaceAll("-", "")}`;
const password = randomUUID();
const registeredEmail = `new-${randomUUID()}@example.com`;
const registeredPassword = `registered-${randomUUID()}`;
const duplicatePassword = `duplicate-${randomUUID()}`;
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const oidcPrivateKeyBase64 = Buffer.from(
  privateKey.export({ type: "pkcs8", format: "pem" })
).toString("base64");
const mongo = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
const listener = createServer();
listener.listen(0, "127.0.0.1");
await once(listener, "listening");
const port = listener.address().port;
await new Promise((resolve) => listener.close(resolve));
const base = `http://127.0.0.1:${port}`;
const cookies = new Map();
let child;
async function start() {
  child = spawn(process.execPath, ["dist/server.js"], {
    cwd: fileURLToPath(new URL(".", import.meta.url)),
    windowsHide: true,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(port),
      PUBLIC_ORIGIN: base,
      MONGODB_URI: uri,
      MONGODB_DATABASE: database,
      DEMO_PASSWORD: password,
      OIDC_PRIVATE_KEY_BASE64: oidcPrivateKeyBase64,
      OIDC_KEY_ID: "e2e-key",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Do not echo process output: startup errors might contain connection credentials.
  child.stderr.resume();
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Example startup timed out")), 20_000);
    child.once("error", () => {
      clearTimeout(timer);
      reject(new Error("Example failed to start"));
    });
    child.once("exit", () => {
      clearTimeout(timer);
      reject(new Error("Example exited before startup"));
    });
    child.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("OIDC example ready")) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
}
async function stop() {
  if (child && child.exitCode === null && child.signalCode === null) {
    const closed = once(child, "exit");
    child.kill("SIGTERM");
    await closed;
  }
}
async function http(
  path,
  { method = "GET", form, jar = cookies, origin = base, requestHeaders = {} } = {}
) {
  const url = new URL(path, base);
  assert.equal(url.origin, base, "Never send test cookies to a different origin");
  const response = await fetch(url, {
    method,
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
    headers: {
      Cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; "),
      ...(method === "POST" && origin ? { Origin: origin } : {}),
      ...requestHeaders,
    },
    ...(form ? { body: new URLSearchParams(form) } : {}),
  });
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";", 1)[0];
    const separator = pair.indexOf("=");
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (!value || /max-age=0/i.test(header)) jar.delete(name);
    else jar.set(name, value);
  }
  return {
    status: response.status,
    location: response.headers.get("location"),
    contentType: response.headers.get("content-type"),
    contentSecurityPolicy: response.headers.get("content-security-policy"),
    retryAfter: response.headers.get("retry-after"),
    text: await response.text(),
  };
}
function hiddenField(html, name) {
  const match = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert.ok(match, `Form contains ${name}`);
  return match[1];
}
function fields(html) {
  return Object.fromEntries(
    ["transaction", "csrf_token"].map((name) => [name, hiddenField(html, name)])
  );
}
async function consentForm() {
  const start = await http("/demo/start");
  assert.equal(start.status, 302);
  const request = new URL(start.location);
  assert.equal(request.searchParams.get("scope"), "openid profile email");
  assert.ok(request.searchParams.get("nonce"));
  const authorization = await http(start.location);
  assert.equal(authorization.status, 302);
  const page = await http(authorization.location);
  assert.equal(page.status, 200);
  return page;
}
try {
  await mongo.connect();
  await start();
  const health = await http("/health");
  assert.equal(health.status, 200);
  assert.deepEqual(JSON.parse(health.text), { ready: true });
  const home = await http("/");
  assert.equal(home.status, 200);
  assert.match(home.text, /Continue to identity provider/);
  assert.match(home.text, /Create account/);
  assert.match(home.contentSecurityPolicy, /style-src 'self'/);
  assert.match((await http("/app.css")).contentType, /^text\/css/);
  assert.equal((await http("/auth/.well-known/oauth-authorization-server")).status, 200);
  const discovery = await http("/auth/.well-known/openid-configuration");
  assert.equal(discovery.status, 200);
  assert.deepEqual(JSON.parse(discovery.text), {
    ...JSON.parse((await http("/auth/.well-known/oauth-authorization-server")).text),
    userinfo_endpoint: `${base}/auth/userinfo`,
    jwks_uri: `${base}/auth/.well-known/jwks.json`,
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["sub", "email", "name"],
  });
  const jwks = await http("/auth/.well-known/jwks.json");
  assert.equal(jwks.status, 200);
  assert.equal(JSON.parse(jwks.text).keys[0].kid, "e2e-key");
  assert.equal((await http("/api/profile")).status, 401);
  let registration = await http("/register");
  assert.equal(registration.status, 200);
  assert.match(registration.text, /Create your account/);
  const invalidRegistrationCsrf = await http("/register", {
    method: "POST",
    form: {
      csrf_token: "wrong",
      email: registeredEmail,
      password: registeredPassword,
      confirm_password: registeredPassword,
    },
  });
  assert.equal(invalidRegistrationCsrf.status, 400);
  registration = await http("/register");
  const mismatch = await http("/register", {
    method: "POST",
    form: {
      csrf_token: hiddenField(registration.text, "csrf_token"),
      email: registeredEmail,
      password: registeredPassword,
      confirm_password: duplicatePassword,
    },
  });
  assert.equal(mismatch.status, 400);
  assert.match(mismatch.text, /passwords do not match/);
  const registered = await http("/register", {
    method: "POST",
    form: {
      csrf_token: hiddenField(mismatch.text, "csrf_token"),
      email: ` ${registeredEmail.toUpperCase()} `,
      password: registeredPassword,
      confirm_password: registeredPassword,
    },
  });
  assert.equal(registered.status, 303);
  assert.equal(registered.location, "/register/complete");
  assert.match((await http(registered.location)).text, /Continue to sign in/);
  registration = await http("/register");
  const duplicate = await http("/register", {
    method: "POST",
    form: {
      csrf_token: hiddenField(registration.text, "csrf_token"),
      email: registeredEmail,
      password: duplicatePassword,
      confirm_password: duplicatePassword,
    },
  });
  assert.equal(duplicate.status, 303, "Duplicate registration uses the generic completion flow");
  for (const path of [
    "/register",
    "/auth/login",
    "/auth/consent",
    "/auth/logout",
    "/demo/revoke",
    "/demo/logout",
  ]) {
    for (const variant of [path, `${path}/`, path.toUpperCase()]) {
      assert.equal(
        (await http(variant, { method: "POST", origin: "https://attacker.example" })).status,
        403,
        "Origin checks cover every equivalent Express route"
      );
    }
  }
  assert.equal(
    (
      await http("/demo/revoke", {
        method: "POST",
        origin: `http://localhost:${port}`,
        jar: new Map(),
      })
    ).status,
    302,
    "Localhost and 127.0.0.1 are equivalent outside production"
  );
  assert.equal(
    (
      await http("/demo/revoke", {
        method: "POST",
        origin: null,
        requestHeaders: { "Sec-Fetch-Site": "same-origin" },
        jar: new Map(),
      })
    ).status,
    302,
    "Same-origin browser metadata covers clients that omit Origin"
  );
  let limitedPage = await consentForm();
  let limitedForm = fields(limitedPage.text);
  for (let attempt = 1; attempt <= 11; attempt += 1) {
    const response = await http("/auth/login", {
      method: "POST",
      form: {
        ...limitedForm,
        email: "limited@example.com",
        password: "incorrect-password",
      },
    });
    if (attempt <= 10) {
      assert.equal(response.status, 200);
      limitedForm = fields(response.text);
    } else {
      assert.equal(response.status, 429);
      assert.match(response.text, /Too many sign-in attempts/);
      assert.ok(Number(response.retryAfter) > 0);
    }
  }
  let page = await consentForm();
  let form = fields(page.text);
  const invalidCsrf = await http("/auth/login", {
    method: "POST",
    form: { ...form, csrf_token: "wrong", email: registeredEmail, password: registeredPassword },
  });
  assert.equal(invalidCsrf.status, 400);
  const failedLogin = await http("/auth/login", {
    method: "POST",
    form: { ...form, email: registeredEmail, password: duplicatePassword },
  });
  assert.equal(failedLogin.status, 200);
  assert.ok(failedLogin.text.includes("incorrect"));
  form = fields(failedLogin.text);
  const login = await http("/auth/login", {
    method: "POST",
    form: { ...form, email: registeredEmail.toUpperCase(), password: registeredPassword },
  });
  assert.equal(login.status, 302);
  page = await http(login.location);
  const allowed = await http("/auth/consent", {
    method: "POST",
    form: { ...fields(page.text), decision: "allow" },
  });
  assert.equal(allowed.status, 302);
  const altered = new URL(allowed.location);
  altered.searchParams.set("state", "incorrect-state");
  assert.equal((await http(altered)).status, 400);
  assert.equal((await http(allowed.location, { jar: new Map() })).status, 400);

  // Restart before callback: verifier, browser binding, code, and IdP session must survive.
  await stop();
  await start();
  const callback = await http(allowed.location);
  assert.equal(callback.status, 302);
  assert.equal(callback.location, "/demo/profile");
  const profile = await http(callback.location);
  assert.equal(profile.status, 200);
  assert.match(profile.contentType, /^text\/html/);
  assert.match(profile.text, /Demo app verified your identity/);
  assert.match(profile.text, /OIDC subject/);
  assert.match(profile.text, new RegExp(registeredEmail));
  assert.match(profile.text, />openid, profile, email</);
  assert.equal((await http(allowed.location)).status, 400, "Callback is single-use");
  assert.equal((await http("/api/session")).status, 200);

  // Restart again: both client access and browser session remain usable.
  await stop();
  await start();
  assert.deepEqual(
    JSON.parse((await http("/auth/.well-known/jwks.json")).text),
    JSON.parse(jwks.text),
    "OIDC signing key survives process restarts"
  );
  assert.equal((await http("/demo/profile")).status, 200);
  assert.equal((await http("/api/session")).status, 200);
  const storedUser = await mongo
    .db(database)
    .collection("demo_users")
    .findOne({ _id: "demo-user" });
  assert.equal(typeof storedUser?.passwordHash, "string");
  assert.ok(storedUser.passwordHash !== password && !("password" in storedUser));
  const registeredUser = await mongo
    .db(database)
    .collection("demo_users")
    .findOne({ email: registeredEmail });
  assert.equal(typeof registeredUser?.passwordHash, "string");
  assert.ok(registeredUser.passwordHash !== registeredPassword && !("password" in registeredUser));
  assert.equal(
    await mongo.db(database).collection("demo_users").countDocuments({ email: registeredEmail }),
    1
  );
  assert.equal(
    (await http("/demo/revoke", { method: "POST", origin: "https://attacker.example" })).status,
    403
  );
  const retainedCookie = new Map(cookies);
  assert.equal((await http("/demo/revoke", { method: "POST" })).status, 302);
  assert.equal((await http("/demo/profile", { jar: retainedCookie })).status, 401);
  const storedToken = await mongo
    .db(database)
    .collection("zero_auth_idp_access_tokens")
    .findOne({ clientId: "demo-app" });
  assert.equal(typeof storedToken?.revokedAt, "number");
  assert.equal((await http("/demo/logout", { method: "POST", jar: retainedCookie })).status, 302);
  assert.equal((await http("/api/session", { jar: retainedCookie })).status, 401);

  // Denial is bound to state too, and issues no client access.
  page = await consentForm();
  const secondLogin = await http("/auth/login", {
    method: "POST",
    form: { ...fields(page.text), email: registeredEmail, password: registeredPassword },
  });
  page = await http(secondLogin.location);
  const denied = await http("/auth/consent", {
    method: "POST",
    form: { ...fields(page.text), decision: "deny" },
  });
  const deniedCallback = await http(denied.location);
  assert.equal(deniedCallback.status, 400);
  assert.match(deniedCallback.text, /No access was granted/);
  console.log(
    "PASS: registration, unique normalized email, OIDC verification, UserInfo, PKCE callback, restarts, revocation, logout, denial"
  );
} finally {
  await stop();
  try {
    if (!/^zero_auth_example_test_[a-f0-9]{32}$/.test(database))
      throw new Error("Unsafe test cleanup target");
    await mongo.db(database).dropDatabase();
  } finally {
    await mongo.close();
  }
}
