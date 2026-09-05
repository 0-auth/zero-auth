import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  OAuthStorage,
  SessionRecord,
} from "./types.js";

export class MemoryOAuthStorage implements OAuthStorage {
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly transactions = new Map<string, AuthorizationTransaction>();
  private readonly authorizationCodes = new Map<string, AuthorizationCodeRecord>();
  private readonly accessTokens = new Map<string, AccessTokenRecord>();

  saveSession(record: SessionRecord): void {
    this.sessions.set(record.tokenHash, record);
  }

  getSession(tokenHash: string): SessionRecord | null {
    const record = this.sessions.get(tokenHash);
    if (!record || record.expiresAt <= Date.now()) return null;
    return record;
  }

  revokeSession(tokenHash: string): void {
    this.sessions.delete(tokenHash);
  }

  saveTransaction(record: AuthorizationTransaction): void {
    this.transactions.set(record.id, record);
  }

  getTransaction(id: string): AuthorizationTransaction | null {
    const record = this.transactions.get(id);
    if (!record || record.expiresAt <= Date.now()) {
      this.transactions.delete(id);
      return null;
    }
    return record;
  }

  deleteTransaction(id: string): void {
    this.transactions.delete(id);
  }

  saveAuthorizationCode(record: AuthorizationCodeRecord): void {
    this.authorizationCodes.set(record.codeHash, record);
  }

  consumeAuthorizationCode(
    codeHash: string,
    expected: {
      clientId: string;
      redirectUri: string;
      codeChallenge: string;
    }
  ): AuthorizationCodeRecord | null {
    const record = this.authorizationCodes.get(codeHash);
    if (
      !record ||
      record.expiresAt <= Date.now() ||
      record.clientId !== expected.clientId ||
      record.redirectUri !== expected.redirectUri ||
      record.codeChallenge !== expected.codeChallenge
    ) {
      return null;
    }

    this.authorizationCodes.delete(codeHash);
    return record;
  }

  saveAccessToken(record: AccessTokenRecord): void {
    this.accessTokens.set(record.tokenHash, record);
  }

  getAccessToken(tokenHash: string): AccessTokenRecord | null {
    return this.accessTokens.get(tokenHash) ?? null;
  }

  revokeAccessToken(tokenHash: string): void {
    const record = this.accessTokens.get(tokenHash);
    if (!record) return;
    this.accessTokens.set(tokenHash, { ...record, revokedAt: Date.now() });
  }
}

export function createMemoryOAuthStorage(): OAuthStorage {
  return new MemoryOAuthStorage();
}
