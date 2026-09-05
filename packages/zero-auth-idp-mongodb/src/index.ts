import type { Collection, Db } from "mongodb";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  OAuthStorage,
  SessionRecord,
} from "@0-auth/zero-auth-idp";

type MongoRecord<T> = Omit<T, "expiresAt"> & { _id: string; expiresAt: Date };

export interface MongoOAuthStorageOptions {
  collectionPrefix?: string;
}

function clean(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;

  return Object.fromEntries(
    Object.entries(value)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key, clean(entry)])
  );
}

function withId<T extends { expiresAt: number }>(record: T, id: string): MongoRecord<T> {
  return { ...(clean(record) as T), _id: id, expiresAt: new Date(record.expiresAt) };
}

function withoutId<T extends { _id: string; expiresAt: Date }>(record: T) {
  const { _id: _ignored, expiresAt, ...value } = record;
  return { ...value, expiresAt: expiresAt.getTime() };
}

function ttlIndexName(collection: string): string {
  return `${collection}_expiresAt_ttl`;
}

export class MongoOAuthStorage implements OAuthStorage {
  private readonly sessions: Collection<MongoRecord<SessionRecord>>;
  private readonly transactions: Collection<MongoRecord<AuthorizationTransaction>>;
  private readonly authorizationCodes: Collection<MongoRecord<AuthorizationCodeRecord>>;
  private readonly accessTokens: Collection<MongoRecord<AccessTokenRecord>>;

  constructor(db: Db, options: MongoOAuthStorageOptions = {}) {
    const prefix = options.collectionPrefix ?? "zero_auth_idp";
    this.sessions = db.collection(`${prefix}_sessions`);
    this.transactions = db.collection(`${prefix}_transactions`);
    this.authorizationCodes = db.collection(`${prefix}_authorization_codes`);
    this.accessTokens = db.collection(`${prefix}_access_tokens`);
  }

  async ensureIndexes(): Promise<void> {
    await Promise.all([
      this.sessions.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: ttlIndexName(this.sessions.collectionName) }
      ),
      this.transactions.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: ttlIndexName(this.transactions.collectionName) }
      ),
      this.authorizationCodes.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: ttlIndexName(this.authorizationCodes.collectionName) }
      ),
      this.accessTokens.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: ttlIndexName(this.accessTokens.collectionName) }
      ),
    ]);
  }

  async saveSession(record: SessionRecord): Promise<void> {
    await this.sessions.replaceOne({ _id: record.tokenHash }, withId(record, record.tokenHash), {
      upsert: true,
    });
  }

  async getSession(tokenHash: string): Promise<SessionRecord | null> {
    const record = await this.sessions.findOne({
      _id: tokenHash,
      expiresAt: { $gt: new Date() },
    });
    return record ? withoutId(record) : null;
  }

  async revokeSession(tokenHash: string): Promise<void> {
    await this.sessions.deleteOne({ _id: tokenHash });
  }

  async saveTransaction(record: AuthorizationTransaction): Promise<void> {
    await this.transactions.replaceOne({ _id: record.id }, withId(record, record.id), {
      upsert: true,
    });
  }

  async getTransaction(id: string): Promise<AuthorizationTransaction | null> {
    const record = await this.transactions.findOne({
      _id: id,
      expiresAt: { $gt: new Date() },
    });
    return record ? withoutId(record) : null;
  }

  async deleteTransaction(id: string): Promise<void> {
    await this.transactions.deleteOne({ _id: id });
  }

  async saveAuthorizationCode(record: AuthorizationCodeRecord): Promise<void> {
    await this.authorizationCodes.replaceOne(
      { _id: record.codeHash },
      withId(record, record.codeHash),
      { upsert: true }
    );
  }

  async consumeAuthorizationCode(
    codeHash: string,
    expected: {
      clientId: string;
      redirectUri: string;
      codeChallenge: string;
    }
  ): Promise<AuthorizationCodeRecord | null> {
    const record = await this.authorizationCodes.findOneAndDelete({
      _id: codeHash,
      clientId: expected.clientId,
      redirectUri: expected.redirectUri,
      codeChallenge: expected.codeChallenge,
      expiresAt: { $gt: new Date() },
    });
    return record ? withoutId(record) : null;
  }

  async saveAccessToken(record: AccessTokenRecord): Promise<void> {
    await this.accessTokens.replaceOne(
      { _id: record.tokenHash },
      withId(record, record.tokenHash),
      {
        upsert: true,
      }
    );
  }

  async getAccessToken(tokenHash: string): Promise<AccessTokenRecord | null> {
    const record = await this.accessTokens.findOne({ _id: tokenHash });
    return record ? withoutId(record) : null;
  }

  async revokeAccessToken(tokenHash: string): Promise<void> {
    await this.accessTokens.updateOne({ _id: tokenHash }, { $set: { revokedAt: Date.now() } });
  }
}

export function createMongoOAuthStorage(
  db: Db,
  options?: MongoOAuthStorageOptions
): MongoOAuthStorage {
  return new MongoOAuthStorage(db, options);
}
