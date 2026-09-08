import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import express, {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import { createMemoryOAuthStorage } from "./storage.js";
import { createOidcRuntime, type OidcRuntime } from "./oidc.js";
import { defaultUi } from "./ui.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  IdentityProvider,
  IdentityProviderConfig,
  IdentityProviderEvent,
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

function quoteHeaderValue(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
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
  if (!origin) return request.get("sec-fetch-site") === "same-origin";

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
    "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
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
  description: string,
  issuer?: string
): void {
  setSecurityHeaders(response);
  const location = new URL(redirectUri);
  location.searchParams.set("error", code);
  location.searchParams.set("error_description", description);
  if (state) location.searchParams.set("state", state);
  if (issuer) location.searchParams.set("iss", issuer);
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
    if (parsed.username || parsed.password) {
      throw new Error("OAuth redirect URIs must not contain credentials.");
    }
    if (["javascript:", "data:", "file:", "vbscript:"].includes(parsed.protocol)) {
      throw new Error("OAuth redirect URIs must use a safe URI scheme.");
    }
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
  const issuerUrl = new URL(config.issuer);
  if (
    !["http:", "https:"].includes(issuerUrl.protocol) ||
    issuerUrl.username ||
    issuerUrl.password ||
    issuerUrl.search ||
    issuerUrl.hash
  ) {
    throw new Error("issuer must be an HTTP(S) URL without credentials, query, or fragment.");
  }
  const issuer = issuerUrl.toString().replace(/\/$/, "");
  const oidc: OidcRuntime | null = config.oidc ? createOidcRuntime(issuer, config.oidc) : null;
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
    secure:
      config.cookie?.secure ??
      (issuerUrl.protocol === "https:" || process.env["NODE_ENV"] === "production"),
    sameSite: config.cookie?.sameSite ?? "lax",
    path: config.cookie?.path ?? "/",
  } satisfies Required<NonNullable<IdentityProviderConfig["cookie"]>>;
  if (cookie.sameSite === "none" && !cookie.secure) {
    throw new Error("SameSite=None requires secure cookies.");
  }
  let logoutRedirectUri: string | undefined;
  if (config.logoutRedirectUri) {
    const parsed = new URL(config.logoutRedirectUri);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
      throw new Error("logoutRedirectUri must be an HTTP(S) URL without credentials.");
    }
    logoutRedirectUri = parsed.toString();
  }

  const clients = new Map<string, OAuthClient>();
  for (const client of config.clients) {
    validateClient(client);
    if (client.allowedScopes.includes("openid") && !oidc) {
      throw new Error(
        `OAuth client ${client.clientId} requires oidc configuration for openid scope.`
      );
    }
    if (clients.has(client.clientId)) throw new Error(`Duplicate OAuth client ${client.clientId}.`);
    clients.set(client.clientId, client);
  }
  if (clients.size === 0) throw new Error("At least one OAuth client is required.");
  const scopesSupported = [
    ...new Set([...clients.values()].flatMap((client) => client.allowedScopes)),
  ];

  const ui: Required<IdentityProviderUi> = {
    ...defaultUi,
    ...config.ui,
  };

  async function emitEvent(event: IdentityProviderEvent): Promise<void> {
    if (!config.onEvent) return;
    try {
      await config.onEvent(event);
    } catch {
      // ponytail: best-effort telemetry; auth requests must not depend on sink availability.
    }
  }

  async function getSession(
    request: Request
  ): Promise<{ token: string; record: SessionRecord } | null> {
    const token = getCookie(request, cookie.name);
    if (!token) return null;
    const record = await storage.getSession(hashToken(token));
    return record && record.expiresAt > Date.now() ? { token, record } : null;
  }

  async function getTransaction(request: Request): Promise<AuthorizationTransaction | null> {
    const id = queryValue(request, "transaction") ?? formValue(request, "transaction");
    if (!id || !/^[A-Za-z0-9_-]{20,}$/.test(id)) return null;
    const transaction = await storage.getTransaction(id);
    return transaction && transaction.expiresAt > Date.now() ? transaction : null;
  }

  async function renderLoginPage(
    request: Request,
    response: Response,
    transaction: AuthorizationTransaction,
    error?: string,
    email?: string
  ): Promise<void> {
    const client = clients.get(transaction.clientId);
    if (!client) throw new OAuthServerError("invalid_client", "OAuth client was not found.");
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
        clientName: client.name ?? client.clientId,
        ...(email ? { email } : {}),
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
    const nonce = queryValue(request, "nonce") ?? undefined;
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
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "invalid_request",
        "The state is too long.",
        issuer
      );
      return;
    }
    if (queryValue(request, "response_type") !== "code") {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "unsupported_response_type",
        "Only code is supported.",
        issuer
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
        "The requested scope is invalid.",
        issuer
      );
      return;
    }
    if (scopes.some((scope) => !client.allowedScopes.includes(scope))) {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "invalid_scope",
        "The requested scope is not allowed.",
        issuer
      );
      return;
    }
    if (scopes.includes("openid") && (!oidc || !nonce || nonce.length > 2048)) {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "invalid_request",
        "A nonce is required for openid authorization.",
        issuer
      );
      return;
    }
    if (
      !codeChallenge ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge) ||
      queryValue(request, "code_challenge_method") !== "S256"
    ) {
      redirectOAuthError(
        response,
        redirectUri,
        state,
        "invalid_request",
        "PKCE S256 is required.",
        issuer
      );
      return;
    }

    const id = randomToken(24);
    const session = await getSession(request);
    const transaction: AuthorizationTransaction = {
      id,
      clientId: client.clientId,
      redirectUri,
      scopes,
      codeChallenge,
      createdAt: Date.now(),
      expiresAt: Date.now() + authorizationCodeTtlSeconds * 1000,
      ...(state ? { state } : {}),
      ...(scopes.includes("openid") && nonce ? { nonce } : {}),
      ...(session ? { authTime: session.record.createdAt } : {}),
    };
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
      if (transaction) {
        await emitEvent({
          type: "login_failed",
          clientId: transaction.clientId,
          reason: "invalid_form",
        });
      }
      sendHtml(response, ui.renderError({ message: "The login form is invalid or expired." }), 400);
      return;
    }

    const email = formValue(request, "email");
    const password = formValue(request, "password");
    if (!email || !password) {
      await emitEvent({
        type: "login_failed",
        clientId: transaction.clientId,
        reason: "invalid_form",
      });
      await renderLoginPage(
        request,
        response,
        transaction,
        "Email and password are required.",
        email ?? undefined
      );
      return;
    }

    const user = await config.authenticateUser({ email, password }, request);
    if (!user) {
      await emitEvent({
        type: "login_failed",
        clientId: transaction.clientId,
        reason: "invalid_credentials",
      });
      await renderLoginPage(
        request,
        response,
        transaction,
        "The email or password is incorrect.",
        email
      );
      return;
    }

    const sessionToken = randomToken();
    await storage.saveSession({
      tokenHash: hashToken(sessionToken),
      user,
      createdAt: Date.now(),
      expiresAt: Date.now() + sessionTtlSeconds * 1000,
    });
    await storage.saveTransaction({
      ...transaction,
      user,
      ...(transaction.scopes.includes("openid") ? { authTime: Date.now() } : {}),
    });
    await emitEvent({
      type: "login_succeeded",
      clientId: transaction.clientId,
      userId: user.id,
    });
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
      await emitEvent({
        type: "authorization_denied",
        clientId: transaction.clientId,
        userId: transaction.user.id,
        scopes: [...transaction.scopes],
      });
      redirectOAuthError(
        response,
        transaction.redirectUri,
        transaction.state,
        "access_denied",
        "The user denied access.",
        issuer
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
      ...(transaction.nonce ? { nonce: transaction.nonce } : {}),
      ...(transaction.authTime ? { authTime: transaction.authTime } : {}),
      codeChallenge: transaction.codeChallenge,
      createdAt: Date.now(),
      expiresAt: Date.now() + authorizationCodeTtlSeconds * 1000,
    };
    await storage.saveAuthorizationCode(record);
    await storage.deleteTransaction(transaction.id);

    const location = new URL(transaction.redirectUri);
    location.searchParams.set("code", code);
    if (transaction.state) location.searchParams.set("state", transaction.state);
    location.searchParams.set("iss", issuer);
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
    const accessTokenExpiresAt = Date.now() + accessTokenTtlSeconds * 1000;
    await storage.saveAccessToken({
      tokenHash: hashToken(accessToken),
      clientId: client.clientId,
      user: authorizationCode.user,
      scopes: authorizationCode.scopes,
      createdAt: Date.now(),
      expiresAt: accessTokenExpiresAt,
    });
    const idToken =
      oidc && authorizationCode.scopes.includes("openid") && authorizationCode.nonce
        ? await oidc.signIdToken({
            clientId: client.clientId,
            user: authorizationCode.user,
            nonce: authorizationCode.nonce,
            authTime: authorizationCode.authTime ?? authorizationCode.createdAt,
          })
        : null;
    await emitEvent({
      type: "token_issued",
      clientId: client.clientId,
      userId: authorizationCode.user.id,
      scopes: [...authorizationCode.scopes],
      expiresAt: accessTokenExpiresAt,
    });
    setSecurityHeaders(response);
    response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSeconds,
      scope: authorizationCode.scopes.join(" "),
      ...(idToken ? { id_token: idToken } : {}),
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
      if (record?.clientId === client.clientId) {
        await storage.revokeAccessToken(hashToken(token));
        await emitEvent({
          type: "token_revoked",
          clientId: client.clientId,
          userId: record.user.id,
        });
      }
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

  async function userinfo(request: Request, response: Response): Promise<void> {
    const header = request.headers.authorization;
    const match = typeof header === "string" ? /^Bearer\s+(\S+)$/i.exec(header.trim()) : null;
    const record = match?.[1] ? await storage.getAccessToken(hashToken(match[1])) : null;
    if (!activeToken(record)) {
      setSecurityHeaders(response);
      response.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      response.status(401).json({ error: "invalid_token" });
      return;
    }
    if (!record.scopes.includes("openid")) {
      setSecurityHeaders(response);
      response.setHeader(
        "WWW-Authenticate",
        `Bearer error="insufficient_scope", scope=${quoteHeaderValue("openid")}`
      );
      response.status(403).json({ error: "insufficient_scope" });
      return;
    }

    setSecurityHeaders(response);
    response.json({
      sub: record.user.id,
      ...(record.user.email ? { email: record.user.email } : {}),
      ...(record.user.name ? { name: record.user.name } : {}),
    });
  }

  async function metadata(request: Request, response: Response): Promise<void> {
    setSecurityHeaders(response);
    const document: Record<string, unknown> = {
      issuer,
      authorization_endpoint: endpoint(issuer, "authorize"),
      token_endpoint: endpoint(issuer, "token"),
      revocation_endpoint: endpoint(issuer, "revoke"),
      introspection_endpoint: endpoint(issuer, "introspect"),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      scopes_supported: scopesSupported,
      code_challenge_methods_supported: ["S256"],
      authorization_response_iss_parameter_supported: true,
      token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    };
    if (oidc) {
      Object.assign(document, {
        userinfo_endpoint: endpoint(issuer, "userinfo"),
        jwks_uri: endpoint(issuer, ".well-known/jwks.json"),
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        claims_supported: ["sub", "email", "name"],
      });
    }
    response.json(document);
  }

  async function jwks(_request: Request, response: Response): Promise<void> {
    if (!oidc) {
      sendOAuthError(response, "not_found", "OIDC is not enabled.", 404);
      return;
    }
    setSecurityHeaders(response);
    response.json({ keys: [oidc.publicJwk] });
  }

  function requireSession(): RequestHandler {
    return (request, response, next) => {
      void getSession(request)
        .then((session) => {
          if (!session) {
            setSecurityHeaders(response);
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
          setSecurityHeaders(response);
          response.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
          response.status(401).json({ error: "invalid_token" });
          return;
        }
        if (requiredScopes.some((scope) => !record.scopes.includes(scope))) {
          setSecurityHeaders(response);
          response.setHeader(
            "WWW-Authenticate",
            `Bearer error="insufficient_scope", scope=${quoteHeaderValue(requiredScopes.join(" "))}`
          );
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
    app.use(express.urlencoded({ extended: false, limit: "16kb" }));
    app.get("/.well-known/oauth-authorization-server", asyncRoute(metadata));
    if (oidc) {
      app.get("/.well-known/openid-configuration", asyncRoute(metadata));
      app.get("/.well-known/jwks.json", asyncRoute(jwks));
      app.get("/userinfo", asyncRoute(userinfo));
    }
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
        const session = await getSession(request);
        const token = session?.token ?? getCookie(request, cookie.name);
        if (token) await storage.revokeSession(hashToken(token));
        if (session) {
          await emitEvent({ type: "logout", userId: session.record.user.id });
        }
        clearCookie(response, cookie.name, cookie);
        setSecurityHeaders(response);
        if (logoutRedirectUri) {
          response.redirect(303, logoutRedirectUri);
          return;
        }
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
export { escapeHtml } from "./ui.js";
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
  IdentityProviderEvent,
  IdentityProviderEventHandler,
  IdentityProviderUi,
  IdentityUser,
  LoginContext,
  OAuthClient,
  OAuthRequestContext,
  OAuthStorage,
  OidcConfig,
  SessionRecord,
} from "./types.js";
