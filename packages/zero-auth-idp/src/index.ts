import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import express, {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import { createMemoryOAuthStorage } from "./storage.js";
import { defaultUi } from "./ui.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  IdentityProvider,
  IdentityProviderConfig,
  IdentityProviderUi,
  OAuthClient,
  OAuthRequestContext,
  OAuthStorage,
  SessionRecord,
} from "./types.js";

const DEFAULT_AUTHORIZATION_CODE_TTL = 10 * 60;
const DEFAULT_ACCESS_TOKEN_TTL = 15 * 60;
const DEFAULT_SESSION_TTL = 8 * 60 * 60;

class OAuthServerError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 400
  ) {
    super(message);
    this.name = "OAuthServerError";
  }
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved <= 0) {
    throw new RangeError(`${name} must be a positive integer.`);
  }
  return resolved;
}

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function hashToken(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function sameSecret(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function formValue(request: Request, name: string): string | null {
  return stringValue((request.body as Record<string, unknown> | undefined)?.[name]);
}

function queryValue(request: Request, name: string): string | null {
  return stringValue((request.query as Record<string, unknown>)[name]);
}

function splitScopes(value: string): string[] {
  return [...new Set(value.trim().split(/\s+/).filter(Boolean))];
}

function validScopes(scopes: readonly string[]): boolean {
  return scopes.every((scope) => /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope));
}

function getCookie(request: Request, name: string): string | null {
  const header = request.headers.cookie;
  if (!header) return null;

  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    if (key !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1));
    } catch {
      return null;
    }
  }

  return null;
}

function setCookie(
  response: Response,
  name: string,
  value: string,
  options: Required<NonNullable<IdentityProviderConfig["cookie"]>>,
  maxAge: number
): void {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${maxAge}`,
    `Path=${options.path}`,
    "HttpOnly",
    `SameSite=${options.sameSite}`,
  ];
  if (options.secure) attributes.push("Secure");
  response.append("Set-Cookie", attributes.join("; "));
}

function clearCookie(
  response: Response,
  name: string,
  options: Required<NonNullable<IdentityProviderConfig["cookie"]>>
): void {
  setCookie(response, name, "", options, 0);
}

function endpoint(issuer: string, path: string): string {
  const base = issuer.endsWith("/") ? issuer : `${issuer}/`;
  return new URL(path.replace(/^\//, ""), base).toString();
}

function routePath(request: Request, path: string): string {
  const base = request.baseUrl || "";
  return `${base.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

function isSameOrigin(request: Request, issuer: string): boolean {
  const origin = request.get("origin") ?? request.get("referer");
  if (!origin) return true;

  try {
    return new URL(origin).origin === new URL(issuer).origin;
  } catch {
    return false;
  }
}

function setSecurityHeaders(response: Response): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
  );
}

function sendOAuthError(
  response: Response,
  code: string,
  description: string,
  statusCode = 400
): void {
  setSecurityHeaders(response);
  response.status(statusCode).json({ error: code, error_description: description });
}

function sendHtml(response: Response, html: string, statusCode = 200): void {
  setSecurityHeaders(response);
  response.status(statusCode).type("html").send(html);
}

function redirectOAuthError(
  response: Response,
  redirectUri: string,
  state: string | undefined,
  code: string,
  description: string
): void {
  const location = new URL(redirectUri);
  location.searchParams.set("error", code);
  location.searchParams.set("error_description", description);
  if (state) location.searchParams.set("state", state);
  response.redirect(location.toString());
}

function asyncRoute(
  handler: (request: Request, response: Response, next: NextFunction) => Promise<void>
): RequestHandler {
  return (request, response, next) => {
    void handler(request, response, next).catch(next);
  };
}

function validateClient(client: OAuthClient): void {
  if (!client.clientId || client.clientId.includes(" ")) {
    throw new Error("OAuth clientId must be a non-empty value without spaces.");
  }
  if (client.clientType === "confidential" && !client.clientSecret) {
    throw new Error(`OAuth confidential client ${client.clientId} needs a clientSecret.`);
  }
  if (client.redirectUris.length === 0) {
    throw new Error(`OAuth client ${client.clientId} needs a redirect URI.`);
  }
  if (!validScopes(client.allowedScopes)) {
    throw new Error(`OAuth client ${client.clientId} has an invalid scope.`);
  }
  for (const redirectUri of client.redirectUris) {
    const parsed = new URL(redirectUri);
    if (parsed.hash) throw new Error("OAuth redirect URIs must not contain fragments.");
  }
}

function parseBasicCredentials(
  request: Request
): { clientId: string; clientSecret: string } | null {
  const header = request.headers.authorization;
  if (!header || !/^Basic\s+/i.test(header)) return null;

  try {
    const encoded = header.replace(/^Basic\s+/i, "");
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return {
      clientId: decodeURIComponent(decoded.slice(0, separator)),
      clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
    };
  } catch {
    return null;
  }
}

export function createIdentityProvider(config: IdentityProviderConfig): IdentityProvider {
  const issuer = new URL(config.issuer).toString().replace(/\/$/, "");
  const storage: OAuthStorage = config.storage ?? createMemoryOAuthStorage();
  const authorizationCodeTtlSeconds = positiveInteger(
    config.authorizationCodeTtlSeconds,
    DEFAULT_AUTHORIZATION_CODE_TTL,
    "authorizationCodeTtlSeconds"
  );
  const accessTokenTtlSeconds = positiveInteger(
    config.accessTokenTtlSeconds,
    DEFAULT_ACCESS_TOKEN_TTL,
    "accessTokenTtlSeconds"
  );
  const sessionTtlSeconds = positiveInteger(
    config.sessionTtlSeconds,
    DEFAULT_SESSION_TTL,
    "sessionTtlSeconds"
  );
  const cookie = {
    name: config.cookie?.name ?? "idp_session",
    secure: config.cookie?.secure ?? process.env["NODE_ENV"] === "production",
    sameSite: config.cookie?.sameSite ?? "lax",
    path: config.cookie?.path ?? "/",
  } satisfies Required<NonNullable<IdentityProviderConfig["cookie"]>>;
  if (cookie.sameSite === "none" && !cookie.secure) {
    throw new Error("SameSite=None requires secure cookies.");
  }

  const clients = new Map<string, OAuthClient>();
  for (const client of config.clients) {
    validateClient(client);
    if (clients.has(client.clientId)) throw new Error(`Duplicate OAuth client ${client.clientId}.`);
    clients.set(client.clientId, client);
  }
  if (clients.size === 0) throw new Error("At least one OAuth client is required.");

  const ui: Required<IdentityProviderUi> = {
    ...defaultUi,
    ...config.ui,
  };

  async function getSession(
    request: Request
  ): Promise<{ token: string; record: SessionRecord } | null> {
    const token = getCookie(request, cookie.name);
    if (!token) return null;
    const record = await storage.getSession(hashToken(token));
    return record ? { token, record } : null;
  }

  async function getTransaction(request: Request): Promise<AuthorizationTransaction | null> {
    const id = queryValue(request, "transaction") ?? formValue(request, "transaction");
    if (!id || !/^[A-Za-z0-9_-]{20,}$/.test(id)) return null;
    return storage.getTransaction(id);
  }

  async function renderLoginPage(
    request: Request,
    response: Response,
    transaction: AuthorizationTransaction,
    error?: string
  ): Promise<void> {
    const csrfToken = randomToken(24);
    await storage.saveTransaction({
      ...transaction,
      loginCsrfHash: hashToken(csrfToken),
    });
    sendHtml(
      response,
      ui.renderLogin({
        action: routePath(request, "login"),
        transactionId: transaction.id,
        csrfToken,
        ...(error ? { error } : {}),
      })
    );
  }

  async function renderConsentPage(
    request: Request,
    response: Response,
    transaction: AuthorizationTransaction
  ): Promise<void> {
    const client = clients.get(transaction.clientId);
    if (!client) throw new OAuthServerError("invalid_client", "OAuth client was not found.");
    const csrfToken = randomToken(24);
    await storage.saveTransaction({
      ...transaction,
      consentCsrfHash: hashToken(csrfToken),
    });
    sendHtml(
      response,
      ui.renderConsent({
        action: routePath(request, "consent"),
        transactionId: transaction.id,
        csrfToken,
        clientName: client.name ?? client.clientId,
        scopes: transaction.scopes,
      })
    );
  }

  function clientFromRequest(request: Request, bodyClientId: string | null): OAuthClient | null {
    const basic = parseBasicCredentials(request);
    const clientId = basic?.clientId ?? bodyClientId;
    if (!clientId) return null;
    if (basic && bodyClientId && basic.clientId !== bodyClientId) return null;

    const client = clients.get(clientId);
    if (!client) return null;
    if (client.clientType !== "confidential") return client;

    const secret = basic?.clientSecret ?? formValue(request, "client_secret");
    if (!secret || !client.clientSecret || !sameSecret(secret, client.clientSecret)) return null;
    return client;
  }

  function activeToken(record: AccessTokenRecord | null): record is AccessTokenRecord {
    return Boolean(record && !record.revokedAt && record.expiresAt > Date.now());
  }

  async function authorize(request: Request, response: Response): Promise<void> {
    const clientId = queryValue(request, "client_id");
    const redirectUri = queryValue(request, "redirect_uri");
    const state = queryValue(request, "state") ?? undefined;
    const client = clientId ? clients.get(clientId) : undefined;

    if (!client) {
      sendOAuthError(response, "unauthorized_client", "The OAuth client is unknown.");
      return;
    }
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      sendOAuthError(response, "invalid_request", "The redirect URI is not registered.");
      return;
    }
    if (state && state.length > 2048) {
      redirectOAuthError(response, redirectUri, state, "invalid_request", "The state is too long.");
      return;
    }
    if (queryValue(request, "response_type") !== "code") {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "unsupported_response_type",
        "Only code is supported."
      );
      return;
    }

    const requestedScope = queryValue(request, "scope");
    const scopes = requestedScope ? splitScopes(requestedScope) : [];
    const codeChallenge = queryValue(request, "code_challenge");
    if (!requestedScope || scopes.length === 0 || !validScopes(scopes)) {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "invalid_scope",
        "The requested scope is invalid."
      );
      return;
    }
    if (scopes.some((scope) => !client.allowedScopes.includes(scope))) {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "invalid_scope",
        "The requested scope is not allowed."
      );
      return;
    }
    if (
      !codeChallenge ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge) ||
      queryValue(request, "code_challenge_method") !== "S256"
    ) {
      redirectOAuthError(response, redirectUri, state, "invalid_request", "PKCE S256 is required.");
      return;
    }

    const id = randomToken(24);
    const transaction: AuthorizationTransaction = {
      id,
      clientId: client.clientId,
      redirectUri,
      scopes,
      codeChallenge,
      createdAt: Date.now(),
      expiresAt: Date.now() + authorizationCodeTtlSeconds * 1000,
      ...(state ? { state } : {}),
    };
    const session = await getSession(request);
    await storage.saveTransaction(
      session ? { ...transaction, user: session.record.user } : transaction
    );
    if (!session) {
      response.redirect(`${routePath(request, "login")}?transaction=${encodeURIComponent(id)}`);
      return;
    }
    response.redirect(`${routePath(request, "consent")}?transaction=${encodeURIComponent(id)}`);
  }

  async function loginPage(request: Request, response: Response): Promise<void> {
    const transaction = await getTransaction(request);
    if (!transaction) {
      sendHtml(
        response,
        ui.renderError({ message: "This authorization request has expired." }),
        400
      );
      return;
    }
    await renderLoginPage(request, response, transaction);
  }

  async function login(request: Request, response: Response): Promise<void> {
    const transaction = await getTransaction(request);
    const csrfToken = formValue(request, "csrf_token");
    if (
      !transaction ||
      !csrfToken ||
      !transaction.loginCsrfHash ||
      !sameSecret(hashToken(csrfToken), transaction.loginCsrfHash)
    ) {
      sendHtml(response, ui.renderError({ message: "The login form is invalid or expired." }), 400);
      return;
    }

    const email = formValue(request, "email");
    const password = formValue(request, "password");
    if (!email || !password) {
      await renderLoginPage(request, response, transaction, "Email and password are required.");
      return;
    }

    const user = await config.authenticateUser({ email, password }, request);
    if (!user) {
      await renderLoginPage(request, response, transaction, "The email or password is incorrect.");
      return;
    }

    const sessionToken = randomToken();
    await storage.saveSession({
      tokenHash: hashToken(sessionToken),
      user,
      createdAt: Date.now(),
      expiresAt: Date.now() + sessionTtlSeconds * 1000,
    });
    await storage.saveTransaction({ ...transaction, user });
    setCookie(response, cookie.name, sessionToken, cookie, sessionTtlSeconds);
    response.redirect(
      `${routePath(request, "consent")}?transaction=${encodeURIComponent(transaction.id)}`
    );
  }

  async function consentPage(request: Request, response: Response): Promise<void> {
    const transaction = await getTransaction(request);
    const session = await getSession(request);
    if (!transaction) {
      sendHtml(
        response,
        ui.renderError({ message: "This authorization request has expired." }),
        400
      );
      return;
    }
    if (!session || !transaction.user || session.record.user.id !== transaction.user.id) {
      response.redirect(
        `${routePath(request, "login")}?transaction=${encodeURIComponent(transaction.id)}`
      );
      return;
    }
    await renderConsentPage(request, response, transaction);
  }

  async function consent(request: Request, response: Response): Promise<void> {
    const transaction = await getTransaction(request);
    const session = await getSession(request);
    const csrfToken = formValue(request, "csrf_token");
    if (
      !transaction ||
      !session ||
      !transaction.user ||
      transaction.user.id !== session.record.user.id ||
      !csrfToken ||
      !transaction.consentCsrfHash ||
      !sameSecret(hashToken(csrfToken), transaction.consentCsrfHash)
    ) {
      sendHtml(
        response,
        ui.renderError({ message: "The consent form is invalid or expired." }),
        400
      );
      return;
    }

    const client = clients.get(transaction.clientId);
    if (!client) throw new OAuthServerError("invalid_client", "OAuth client was not found.");
    if (formValue(request, "decision") !== "allow") {
      await storage.deleteTransaction(transaction.id);
      redirectOAuthError(
        response,
        transaction.redirectUri,
        transaction.state,
        "access_denied",
        "The user denied access."
      );
      return;
    }

    const code = randomToken();
    const record: AuthorizationCodeRecord = {
      codeHash: hashToken(code),
      clientId: client.clientId,
      user: transaction.user,
      redirectUri: transaction.redirectUri,
      scopes: transaction.scopes,
      codeChallenge: transaction.codeChallenge,
      createdAt: Date.now(),
      expiresAt: Date.now() + authorizationCodeTtlSeconds * 1000,
    };
    await storage.saveAuthorizationCode(record);
    await storage.deleteTransaction(transaction.id);

    const location = new URL(transaction.redirectUri);
    location.searchParams.set("code", code);
    if (transaction.state) location.searchParams.set("state", transaction.state);
    response.redirect(location.toString());
  }

  async function token(request: Request, response: Response): Promise<void> {
    const client = clientFromRequest(request, formValue(request, "client_id"));
    if (!client) {
      response.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
      sendOAuthError(response, "invalid_client", "Client authentication failed.", 401);
      return;
    }
    if (formValue(request, "grant_type") !== "authorization_code") {
      sendOAuthError(response, "unsupported_grant_type", "Only authorization_code is supported.");
      return;
    }

    const code = formValue(request, "code");
    const redirectUri = formValue(request, "redirect_uri");
    const verifier = formValue(request, "code_verifier");
    if (!code || !redirectUri || !verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
      sendOAuthError(
        response,
        "invalid_request",
        "Code, redirect_uri, and code_verifier are required."
      );
      return;
    }

    const authorizationCode = await storage.consumeAuthorizationCode(hashToken(code), {
      clientId: client.clientId,
      redirectUri,
      codeChallenge: pkceChallenge(verifier),
    });
    if (!authorizationCode) {
      sendOAuthError(response, "invalid_grant", "The authorization code is invalid or expired.");
      return;
    }

    const accessToken = randomToken();
    await storage.saveAccessToken({
      tokenHash: hashToken(accessToken),
      clientId: client.clientId,
      user: authorizationCode.user,
      scopes: authorizationCode.scopes,
      createdAt: Date.now(),
      expiresAt: Date.now() + accessTokenTtlSeconds * 1000,
    });
    setSecurityHeaders(response);
    response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSeconds,
      scope: authorizationCode.scopes.join(" "),
    });
  }

  async function revoke(request: Request, response: Response): Promise<void> {
    const client = clientFromRequest(request, formValue(request, "client_id"));
    if (!client) {
      response.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
      sendOAuthError(response, "invalid_client", "Client authentication failed.", 401);
      return;
    }

    const token = formValue(request, "token");
    if (token) {
      const record = await storage.getAccessToken(hashToken(token));
      if (record?.clientId === client.clientId) await storage.revokeAccessToken(hashToken(token));
    }
    setSecurityHeaders(response);
    response.status(200).end();
  }

  async function introspect(request: Request, response: Response): Promise<void> {
    const client = clientFromRequest(request, formValue(request, "client_id"));
    if (!client || client.clientType !== "confidential") {
      response.setHeader("WWW-Authenticate", 'Basic realm="oauth"');
      sendOAuthError(response, "invalid_client", "A confidential client is required.", 401);
      return;
    }

    const tokenValue = formValue(request, "token");
    const record = tokenValue ? await storage.getAccessToken(hashToken(tokenValue)) : null;
    if (!activeToken(record)) {
      setSecurityHeaders(response);
      response.json({ active: false });
      return;
    }

    setSecurityHeaders(response);
    response.json({
      active: true,
      client_id: record.clientId,
      sub: record.user.id,
      scope: record.scopes.join(" "),
      token_type: "Bearer",
      iat: Math.floor(record.createdAt / 1000),
      exp: Math.floor(record.expiresAt / 1000),
    });
  }

  async function metadata(request: Request, response: Response): Promise<void> {
    setSecurityHeaders(response);
    response.json({
      issuer,
      authorization_endpoint: endpoint(issuer, "authorize"),
      token_endpoint: endpoint(issuer, "token"),
      revocation_endpoint: endpoint(issuer, "revoke"),
      introspection_endpoint: endpoint(issuer, "introspect"),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    });
  }

  function requireSession(): RequestHandler {
    return (request, response, next) => {
      void getSession(request)
        .then((session) => {
          if (!session) {
            response.status(401).json({ error: "authentication_required" });
            return;
          }
          request.idpUser = session.record.user;
          next();
        })
        .catch(next);
    };
  }

  function authenticateBearer(requiredScopes: readonly string[] = []): RequestHandler {
    return (request, response, next) => {
      void (async () => {
        const header = request.headers.authorization;
        const match = typeof header === "string" ? /^Bearer\s+(\S+)$/i.exec(header.trim()) : null;
        const record = match?.[1] ? await storage.getAccessToken(hashToken(match[1])) : null;
        if (!activeToken(record)) {
          response.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
          response.status(401).json({ error: "invalid_token" });
          return;
        }
        if (requiredScopes.some((scope) => !record.scopes.includes(scope))) {
          response.setHeader("WWW-Authenticate", 'Bearer error="insufficient_scope"');
          response.status(403).json({ error: "insufficient_scope" });
          return;
        }
        const context: OAuthRequestContext = {
          user: record.user,
          clientId: record.clientId,
          scopes: record.scopes,
        };
        request.oauth = context;
        request.idpUser = record.user;
        next();
      })().catch(next);
    };
  }

  function router(): Router {
    const app = express.Router();
    app.use(express.urlencoded({ extended: false }));
    app.get("/.well-known/oauth-authorization-server", asyncRoute(metadata));
    app.get("/authorize", asyncRoute(authorize));
    app.get("/login", asyncRoute(loginPage));
    app.post("/login", asyncRoute(login));
    app.get("/consent", asyncRoute(consentPage));
    app.post("/consent", asyncRoute(consent));
    app.post("/token", asyncRoute(token));
    app.post("/revoke", asyncRoute(revoke));
    app.post("/introspect", asyncRoute(introspect));
    app.post(
      "/logout",
      asyncRoute(async (request, response) => {
        if (!isSameOrigin(request, issuer)) {
          sendOAuthError(
            response,
            "csrf_invalid",
            "The logout request origin is not allowed.",
            403
          );
          return;
        }
        const token = getCookie(request, cookie.name);
        if (token) await storage.revokeSession(hashToken(token));
        clearCookie(response, cookie.name, cookie);
        setSecurityHeaders(response);
        response.status(204).end();
      })
    );
    return app;
  }

  return {
    router,
    requireSession,
    authenticateBearer,
  };
}

export { MemoryOAuthStorage, createMemoryOAuthStorage } from "./storage.js";
export { OAuthServerError };
export type {
  AccessTokenRecord,
  AuthenticateUser,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  ConsentContext,
  ErrorContext,
  IdentityProvider,
  IdentityProviderConfig,
  IdentityProviderUi,
  IdentityUser,
  LoginContext,
  OAuthClient,
  OAuthRequestContext,
  OAuthStorage,
  SessionRecord,
} from "./types.js";
