import type { Request, RequestHandler, Router } from "express";

export interface IdentityUser {
  id: string;
  email?: string;
  name?: string;
}

export interface OAuthClient {
  clientId: string;
  name?: string;
  clientType?: "public" | "confidential";
  clientSecret?: string;
  redirectUris: readonly string[];
  allowedScopes: readonly string[];
}

export interface SessionRecord {
  tokenHash: string;
  user: IdentityUser;
  createdAt: number;
  expiresAt: number;
}

export interface AuthorizationTransaction {
  id: string;
  clientId: string;
  redirectUri: string;
  scopes: readonly string[];
  state?: string;
  codeChallenge: string;
  user?: IdentityUser;
  loginCsrfHash?: string;
  consentCsrfHash?: string;
  createdAt: number;
  expiresAt: number;
}

export interface AuthorizationCodeRecord {
  codeHash: string;
  clientId: string;
  user: IdentityUser;
  redirectUri: string;
  scopes: readonly string[];
  codeChallenge: string;
  createdAt: number;
  expiresAt: number;
}

export interface AccessTokenRecord {
  tokenHash: string;
  clientId: string;
  user: IdentityUser;
  scopes: readonly string[];
  createdAt: number;
  expiresAt: number;
  revokedAt?: number;
}

export interface OAuthStorage {
  saveSession(record: SessionRecord): Promise<void> | void;
  getSession(tokenHash: string): Promise<SessionRecord | null> | SessionRecord | null;
  revokeSession(tokenHash: string): Promise<void> | void;

  saveTransaction(record: AuthorizationTransaction): Promise<void> | void;
  getTransaction(
    id: string
  ): Promise<AuthorizationTransaction | null> | AuthorizationTransaction | null;
  deleteTransaction(id: string): Promise<void> | void;

  saveAuthorizationCode(record: AuthorizationCodeRecord): Promise<void> | void;
  consumeAuthorizationCode(
    codeHash: string,
    expected: {
      clientId: string;
      redirectUri: string;
      codeChallenge: string;
    }
  ): Promise<AuthorizationCodeRecord | null> | AuthorizationCodeRecord | null;

  saveAccessToken(record: AccessTokenRecord): Promise<void> | void;
  getAccessToken(tokenHash: string): Promise<AccessTokenRecord | null> | AccessTokenRecord | null;
  revokeAccessToken(tokenHash: string): Promise<void> | void;
}

export interface LoginContext {
  action: string;
  transactionId: string;
  csrfToken: string;
  error?: string;
}

export interface ConsentContext {
  action: string;
  transactionId: string;
  csrfToken: string;
  clientName: string;
  scopes: readonly string[];
}

export interface ErrorContext {
  message: string;
}

export interface IdentityProviderUi {
  renderLogin?(context: LoginContext): string;
  renderConsent?(context: ConsentContext): string;
  renderError?(context: ErrorContext): string;
}

export type AuthenticateUser = (
  credentials: { email: string; password: string },
  request: Request
) => Promise<IdentityUser | null> | IdentityUser | null;

export interface IdentityProviderConfig {
  issuer: string;
  clients: readonly OAuthClient[];
  authenticateUser: AuthenticateUser;
  storage?: OAuthStorage;
  ui?: IdentityProviderUi;
  authorizationCodeTtlSeconds?: number;
  accessTokenTtlSeconds?: number;
  sessionTtlSeconds?: number;
  cookie?: {
    name?: string;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
    path?: string;
  };
}

export interface OAuthRequestContext {
  user: IdentityUser;
  clientId: string;
  scopes: readonly string[];
}

export interface IdentityProvider {
  router(): Router;
  requireSession(): RequestHandler;
  authenticateBearer(requiredScopes?: readonly string[]): RequestHandler;
}

declare global {
  namespace Express {
    interface Request {
      idpUser?: IdentityUser;
      oauth?: OAuthRequestContext;
    }
  }
}
