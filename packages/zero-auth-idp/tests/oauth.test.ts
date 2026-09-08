import { createHash, generateKeyPairSync } from "node:crypto";
import express from "express";
import { importJWK, jwtVerify } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createIdentityProvider,
  escapeHtml,
  type IdentityProviderConfig,
  type IdentityProviderEvent,
} from "../src/index.js";
import { createMemoryOAuthStorage } from "../src/storage.js";
import { defaultUi } from "../src/ui.js";

const redirectUri = "http://localhost:4000/callback";
const verifier = "a".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

function hidden(html: string, name: string): string {
  const match = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  if (!match?.[1]) throw new Error(`Missing hidden field: ${name}`);
  return match[1];
}

function locationPath(value: string): string {
  const location = new URL(value, "http://localhost");
  return `${location.pathname}${location.search}`;
}

function createApp(
  options: Partial<
    Pick<IdentityProviderConfig, "issuer" | "logoutRedirectUri" | "oidc" | "onEvent" | "storage">
  > = {}
) {
  const idp = createIdentityProvider({
    issuer: options.issuer ?? "http://localhost:3000/auth",
    clients: [
      {
        clientId: "demo-app",
        name: "Demo app",
        clientType: "public",
        redirectUris: [redirectUri],
        allowedScopes: options.oidc
          ? ["openid", "profile", "projects:read"]
          : ["profile", "projects:read"],
      },
      {
        clientId: "introspector",
        name: "Introspector",
        clientType: "confidential",
        clientSecret: "secret",
        redirectUris: [redirectUri],
        allowedScopes: ["profile"],
      },
    ],
    authenticateUser: ({ email, password }) =>
      email === "user@example.com" && password === "correct"
        ? { id: "user-1", email, name: "Test User" }
        : null,
    ...options,
  });

  const app = express();
  app.use("/auth", idp.router());
  app.get("/session", idp.requireSession(), (req, res) => {
    res.json({ userId: req.idpUser?.id });
  });
  app.get("/projects", idp.authenticateBearer(["projects:read"]), (req, res) => {
    res.json({ userId: req.oauth?.user.id, scopes: req.oauth?.scopes });
  });
  app.get("/admin", idp.authenticateBearer(["admin:read"]), (_req, res) => {
    res.sendStatus(200);
  });
  return app;
}

async function authorize(
  app: express.Express,
  decision = "allow",
  scope = "profile projects:read",
  nonce?: string
) {
  const agent = request.agent(app);
  const start = await agent.get("/auth/authorize").query({
    response_type: "code",
    client_id: "demo-app",
    redirect_uri: redirectUri,
    scope,
    state: "state-123",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...(nonce ? { nonce } : {}),
  });
  expect(start.status).toBe(302);

  const loginPage = await agent.get(locationPath(start.headers.location));
  expect(loginPage.status).toBe(200);
  expect(loginPage.text).toContain("Continue to Demo app");
  expect(loginPage.headers["content-security-policy"]).toContain("style-src 'self'");
  const loginTransaction = hidden(loginPage.text, "transaction");
  const loginCsrf = hidden(loginPage.text, "csrf_token");

  const login = await agent.post("/auth/login").type("form").send({
    transaction: loginTransaction,
    csrf_token: loginCsrf,
    email: "user@example.com",
    password: "correct",
  });
  expect(login.status).toBe(302);

  const consentPage = await agent.get(locationPath(login.headers.location));
  expect(consentPage.status).toBe(200);
  const consentTransaction = hidden(consentPage.text, "transaction");
  const consentCsrf = hidden(consentPage.text, "csrf_token");

  const consent = await agent.post("/auth/consent").type("form").send({
    transaction: consentTransaction,
    csrf_token: consentCsrf,
    decision,
  });
  expect(consent.status).toBe(302);

  return { agent, redirect: new URL(consent.headers.location) };
}

describe("OAuth authorization server", () => {
  it("expires temporary storage records and escapes hosted UI values", async () => {
    const storage = createMemoryOAuthStorage();
    expect(await storage.getSession("missing")).toBeNull();
    await storage.saveSession({
      tokenHash: "expired-session",
      user: { id: "user-1" },
      createdAt: 0,
      expiresAt: 1,
    });
    expect(await storage.getSession("expired-session")).toBeNull();
    expect(await storage.getAccessToken("missing")).toBeNull();
    await storage.revokeAccessToken("missing");
    await storage.saveTransaction({
      id: "expired-transaction",
      clientId: "demo-app",
      redirectUri,
      scopes: ["profile"],
      codeChallenge: challenge,
      createdAt: 0,
      expiresAt: 1,
    });

    expect(await storage.getTransaction("expired-transaction")).toBeNull();
    expect(escapeHtml(`&< >"'`)).toBe("&amp;&lt; &gt;&quot;&#39;");
    expect(
      defaultUi.renderLogin({
        action: "/login",
        transactionId: "transaction",
        csrfToken: "csrf",
        clientName: "<Demo app>",
        email: `person"@example.com`,
        error: "Try again",
      })
    ).toContain("Continue to &lt;Demo app&gt;");
    expect(
      defaultUi.renderLogin({
        action: "/login",
        transactionId: "transaction",
        csrfToken: "csrf",
        clientName: "Demo app",
        email: `person"@example.com`,
      })
    ).toContain(`value="person&quot;@example.com"`);
    expect(defaultUi.renderError({ message: "<invalid>" })).toContain("&lt;invalid&gt;");
  });

  it("publishes metadata and completes the hosted PKCE flow", async () => {
    const app = createApp();
    const metadata = await request(app).get("/auth/.well-known/oauth-authorization-server");

    expect(metadata.status).toBe(200);
    expect(metadata.body).toMatchObject({
      issuer: "http://localhost:3000/auth",
      authorization_endpoint: "http://localhost:3000/auth/authorize",
      token_endpoint: "http://localhost:3000/auth/token",
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["profile", "projects:read"],
      authorization_response_iss_parameter_supported: true,
    });

    const result = await authorize(app);
    const code = result.redirect.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(result.redirect.searchParams.get("state")).toBe("state-123");
    expect(result.redirect.searchParams.get("iss")).toBe("http://localhost:3000/auth");

    const token = await request(app).post("/auth/token").type("form").send({
      grant_type: "authorization_code",
      client_id: "demo-app",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    expect(token.status).toBe(200);
    expect(token.body).toMatchObject({
      token_type: "Bearer",
      scope: "profile projects:read",
    });
    expect(token.body.access_token).toEqual(expect.any(String));

    const protectedResponse = await request(app)
      .get("/projects")
      .set("Authorization", `Bearer ${token.body.access_token}`);
    expect(protectedResponse.status).toBe(200);
    expect(protectedResponse.body).toEqual({
      userId: "user-1",
      scopes: ["profile", "projects:read"],
    });
    const insufficient = await request(app)
      .get("/admin")
      .set("Authorization", `Bearer ${token.body.access_token}`);
    expect(insufficient.status).toBe(403);
    expect(insufficient.headers["www-authenticate"]).toBe(
      'Bearer error="insufficient_scope", scope="admin:read"'
    );

    const session = await result.agent.get("/session");
    expect(session.body).toEqual({ userId: "user-1" });
  });

  it("supports opt-in OIDC discovery, ID tokens, JWKS, and userinfo", async () => {
    const app = createApp({ oidc: { keyId: "test-key" } });
    const metadata = await request(app).get("/auth/.well-known/openid-configuration");
    expect(metadata.status).toBe(200);
    expect(metadata.body).toMatchObject({
      issuer: "http://localhost:3000/auth",
      userinfo_endpoint: "http://localhost:3000/auth/userinfo",
      jwks_uri: "http://localhost:3000/auth/.well-known/jwks.json",
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    });

    const missingNonce = await request(app).get("/auth/authorize").query({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: redirectUri,
      scope: "openid profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    expect(new URL(missingNonce.headers.location).searchParams.get("error")).toBe(
      "invalid_request"
    );

    const result = await authorize(app, "allow", "openid profile", "nonce-123");
    const token = await request(app)
      .post("/auth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        client_id: "demo-app",
        code: result.redirect.searchParams.get("code"),
        redirect_uri: redirectUri,
        code_verifier: verifier,
      });
    expect(token.status).toBe(200);
    expect(token.body.id_token).toEqual(expect.any(String));

    const jwks = await request(app).get("/auth/.well-known/jwks.json");
    const verificationKey = await importJWK(jwks.body.keys[0], "RS256");
    const verified = await jwtVerify(token.body.id_token, verificationKey, {
      issuer: "http://localhost:3000/auth",
      audience: "demo-app",
    });
    expect(verified.payload).toMatchObject({
      sub: "user-1",
      email: "user@example.com",
      nonce: "nonce-123",
      auth_time: expect.any(Number),
    });

    const userinfo = await request(app)
      .get("/auth/userinfo")
      .set("Authorization", `Bearer ${token.body.access_token}`);
    expect(userinfo.status).toBe(200);
    expect(userinfo.body).toEqual({
      sub: "user-1",
      email: "user@example.com",
      name: "Test User",
    });
  });

  it("accepts a stable RSA signing key for production OIDC", () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => createApp({ oidc: { signingKey: privateKey } })).not.toThrow();
  });

  it("supports introspection, revocation, logout, and code single-use", async () => {
    const app = createApp();
    const result = await authorize(app);
    const code = result.redirect.searchParams.get("code");
    const token = await request(app).post("/auth/token").type("form").send({
      grant_type: "authorization_code",
      client_id: "demo-app",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    const accessToken = token.body.access_token as string;

    const introspected = await request(app)
      .post("/auth/introspect")
      .type("form")
      .auth("introspector", "secret")
      .send({ token: accessToken });
    expect(introspected.body).toMatchObject({
      active: true,
      client_id: "demo-app",
      sub: "user-1",
      scope: "profile projects:read",
    });

    const revoked = await request(app)
      .post("/auth/revoke")
      .type("form")
      .send({ client_id: "demo-app", token: accessToken });
    expect(revoked.status).toBe(200);

    const inactive = await request(app)
      .post("/auth/introspect")
      .type("form")
      .auth("introspector", "secret")
      .send({ token: accessToken });
    expect(inactive.body).toEqual({ active: false });

    const unauthorized = await request(app)
      .get("/projects")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(unauthorized.status).toBe(401);

    const reused = await request(app).post("/auth/token").type("form").send({
      grant_type: "authorization_code",
      client_id: "demo-app",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    expect(reused.status).toBe(400);
    expect(reused.body.error).toBe("invalid_grant");

    const crossOriginLogout = await result.agent
      .post("/auth/logout")
      .set("Origin", "https://evil.example");
    expect(crossOriginLogout.status).toBe(403);
    expect((await result.agent.get("/session")).status).toBe(200);

    const missingOriginLogout = await result.agent.post("/auth/logout");
    expect(missingOriginLogout.status).toBe(403);
    expect((await result.agent.get("/session")).status).toBe(200);

    const sameOriginFetchLogout = await result.agent
      .post("/auth/logout")
      .set("Sec-Fetch-Site", "same-origin");
    expect(sameOriginFetchLogout.status).toBe(204);
    expect((await result.agent.get("/session")).status).toBe(401);
  });

  it("emits redacted lifecycle events without exposing token values", async () => {
    const events: IdentityProviderEvent[] = [];
    const onEvent = (event: IdentityProviderEvent) => {
      events.push(event);
      if (event.type === "login_succeeded") throw new Error("audit sink unavailable");
      if (event.type === "token_issued") (event.scopes as string[]).push("audit-mutated");
    };
    const app = createApp({ onEvent });
    const result = await authorize(app);
    const code = result.redirect.searchParams.get("code");
    const token = await request(app).post("/auth/token").type("form").send({
      grant_type: "authorization_code",
      client_id: "demo-app",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    await request(app)
      .post("/auth/revoke")
      .type("form")
      .send({ client_id: "demo-app", token: token.body.access_token });
    await result.agent.post("/auth/logout").set("Origin", "http://localhost:3000");

    expect(events.map((event) => event.type)).toEqual([
      "login_succeeded",
      "token_issued",
      "token_revoked",
      "logout",
    ]);
    expect(token.body.scope).toBe("profile projects:read");
    expect(JSON.stringify(events)).not.toContain(token.body.access_token);
  });

  it("supports a fixed logout redirect and rejects unsafe redirect URLs", async () => {
    expect(() => createApp({ logoutRedirectUri: "javascript:alert(1)" })).toThrow(
      "logoutRedirectUri must be an HTTP(S) URL without credentials."
    );

    const app = createApp({ logoutRedirectUri: "https://app.example/signed-out" });
    const result = await authorize(app);
    const logout = await result.agent.post("/auth/logout").set("Origin", "http://localhost:3000");
    expect(logout.status).toBe(303);
    expect(logout.headers.location).toBe("https://app.example/signed-out");
    expect((await result.agent.get("/session")).status).toBe(401);
  });

  it("rejects unsafe issuer configuration", () => {
    expect(() => createApp({ issuer: "javascript:alert(1)" })).toThrow(
      "issuer must be an HTTP(S) URL without credentials, query, or fragment."
    );
    expect(() =>
      createIdentityProvider({
        issuer: "http://localhost:3000/auth",
        clients: [
          {
            clientId: "unsafe",
            redirectUris: ["javascript:alert(1)"],
            allowedScopes: ["profile"],
          },
        ],
        authenticateUser: () => null,
      })
    ).toThrow("OAuth redirect URIs must use a safe URI scheme.");
  });

  it("enforces expiry even when a storage adapter returns stale records", async () => {
    const storage = createMemoryOAuthStorage();
    const app = createApp({ storage });
    const result = await authorize(app);
    const getSession = storage.getSession.bind(storage);
    storage.getSession = async (tokenHash) => {
      const record = await getSession(tokenHash);
      return record ? { ...record, expiresAt: Date.now() - 1 } : null;
    };
    expect((await result.agent.get("/session")).status).toBe(401);

    const start = await request(app).get("/auth/authorize").query({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: redirectUri,
      scope: "profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const getTransaction = storage.getTransaction.bind(storage);
    storage.getTransaction = async (id) => {
      const transaction = await getTransaction(id);
      return transaction ? { ...transaction, expiresAt: Date.now() - 1 } : null;
    };
    expect((await request(app).get(locationPath(start.headers.location))).status).toBe(400);
  });

  it("allows only one concurrent exchange of an authorization code", async () => {
    const app = createApp();
    const result = await authorize(app);
    const body = {
      grant_type: "authorization_code",
      client_id: "demo-app",
      code: result.redirect.searchParams.get("code") ?? "",
      redirect_uri: redirectUri,
      code_verifier: verifier,
    };

    const responses = await Promise.all([
      request(app).post("/auth/token").type("form").send(body),
      request(app).post("/auth/token").type("form").send(body),
    ]);

    expect(responses.map((response) => response.status).sort()).toEqual([200, 400]);
  });

  it("rejects weak PKCE and invalid form state", async () => {
    const app = createApp();
    const weakPkce = await request(app).get("/auth/authorize").query({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: redirectUri,
      scope: "profile",
      code_challenge: "weak",
      code_challenge_method: "plain",
    });
    expect(weakPkce.status).toBe(302);
    expect(weakPkce.headers["cache-control"]).toBe("no-store");
    const weakPkceLocation = new URL(weakPkce.headers.location);
    expect(weakPkceLocation.searchParams.get("error")).toBe("invalid_request");
    expect(weakPkceLocation.searchParams.get("iss")).toBe("http://localhost:3000/auth");

    const start = await request(app).get("/auth/authorize").query({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: redirectUri,
      scope: "profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const loginPage = await request(app).get(locationPath(start.headers.location));
    const invalidLogin = await request(app)
      .post("/auth/login")
      .type("form")
      .send({
        transaction: hidden(loginPage.text, "transaction"),
        csrf_token: "wrong",
        email: "user@example.com",
        password: "correct",
      });
    expect(invalidLogin.status).toBe(400);

    const retryStart = await request(app).get("/auth/authorize").query({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: redirectUri,
      scope: "profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const retryPage = await request(app).get(locationPath(retryStart.headers.location));
    const failedLogin = await request(app)
      .post("/auth/login")
      .type("form")
      .send({
        transaction: hidden(retryPage.text, "transaction"),
        csrf_token: hidden(retryPage.text, "csrf_token"),
        email: "user@example.com",
        password: "wrong",
      });
    expect(failedLogin.status).toBe(200);
    expect(failedLogin.text).toContain(`value="user@example.com"`);
  });

  it("secures session cookies when the issuer uses HTTPS", async () => {
    const app = createApp({ issuer: "https://idp.example/auth" });
    const start = await request(app).get("/auth/authorize").query({
      response_type: "code",
      client_id: "demo-app",
      redirect_uri: redirectUri,
      scope: "profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const loginPage = await request(app).get(locationPath(start.headers.location));
    const login = await request(app)
      .post("/auth/login")
      .type("form")
      .send({
        transaction: hidden(loginPage.text, "transaction"),
        csrf_token: hidden(loginPage.text, "csrf_token"),
        email: "user@example.com",
        password: "correct",
      });
    expect(login.headers["set-cookie"][0]).toContain("Secure");
  });

  it("redirects a denial and rejects missing or insufficient bearer access", async () => {
    const app = createApp();
    const denied = await authorize(app, "deny");
    expect(denied.redirect.searchParams.get("error")).toBe("access_denied");
    expect(denied.redirect.searchParams.get("iss")).toBe("http://localhost:3000/auth");

    expect((await request(app).get("/projects")).status).toBe(401);
  });
});
