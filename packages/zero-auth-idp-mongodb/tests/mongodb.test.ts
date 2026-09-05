import type { Db } from "mongodb";
import { describe, expect, it, vi } from "vitest";
import { createMongoOAuthStorage, type MongoOAuthStorage } from "../src/index.js";

type Document = Record<string, unknown> & { _id: string };

function matches(document: Document, filter: Record<string, unknown>): boolean {
  return Object.entries(filter).every(([key, expected]) => {
    const actual = document[key];
    if (expected && typeof expected === "object" && "$gt" in expected) {
      return actual instanceof Date && expected.$gt instanceof Date && actual > expected.$gt;
    }
    return actual === expected;
  });
}

class FakeCollection {
  readonly documents = new Map<string, Document>();
  readonly createIndex = vi.fn(async () => "index");
  readonly collectionName: string;

  constructor(collectionName: string) {
    this.collectionName = collectionName;
  }

  async replaceOne(_filter: Record<string, unknown>, document: Document): Promise<void> {
    this.documents.set(document._id, document);
  }

  async findOne(filter: Record<string, unknown>): Promise<Document | null> {
    return [...this.documents.values()].find((document) => matches(document, filter)) ?? null;
  }

  async findOneAndDelete(filter: Record<string, unknown>): Promise<Document | null> {
    const document = [...this.documents.values()].find((value) => matches(value, filter));
    if (!document) return null;
    this.documents.delete(document._id);
    return document;
  }

  async deleteOne(filter: Record<string, unknown>): Promise<void> {
    const document = [...this.documents.values()].find((value) => matches(value, filter));
    if (document) this.documents.delete(document._id);
  }

  async updateOne(
    filter: Record<string, unknown>,
    update: { $set: Record<string, unknown> }
  ): Promise<void> {
    const document = [...this.documents.values()].find((value) => matches(value, filter));
    if (document) Object.assign(document, update.$set);
  }
}

class FakeDb {
  readonly collections = new Map<string, FakeCollection>();

  collection(name: string): FakeCollection {
    const existing = this.collections.get(name);
    if (existing) return existing;
    const collection = new FakeCollection(name);
    this.collections.set(name, collection);
    return collection;
  }
}

function storage(): { adapter: MongoOAuthStorage; db: FakeDb } {
  const db = new FakeDb();
  const adapter = createMongoOAuthStorage(db as unknown as Db);
  return { adapter, db };
}

describe("MongoOAuthStorage", () => {
  it("persists records, expires temporary records, and creates TTL indexes", async () => {
    const { adapter, db } = storage();
    await adapter.ensureIndexes();
    expect(
      [...db.collections.values()].every(
        (collection) => collection.createIndex.mock.calls.length === 1
      )
    ).toBe(true);

    await adapter.saveSession({
      tokenHash: "session-hash",
      user: { id: "user-1" },
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    });
    expect(await adapter.getSession("session-hash")).toMatchObject({ user: { id: "user-1" } });

    await adapter.saveTransaction({
      id: "expired-transaction",
      clientId: "client",
      redirectUri: "http://localhost/callback",
      scopes: ["profile"],
      codeChallenge: "challenge",
      createdAt: 0,
      expiresAt: 1,
    });
    expect(await adapter.getTransaction("expired-transaction")).toBeNull();

    await adapter.revokeSession("session-hash");
    expect(await adapter.getSession("session-hash")).toBeNull();
  });

  it("atomically consumes an authorization code once", async () => {
    const { adapter } = storage();
    await adapter.saveAuthorizationCode({
      codeHash: "code-hash",
      clientId: "client",
      user: { id: "user-1" },
      redirectUri: "http://localhost/callback",
      scopes: ["profile"],
      codeChallenge: "challenge",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    });

    const results = await Promise.all([
      adapter.consumeAuthorizationCode("code-hash", {
        clientId: "client",
        redirectUri: "http://localhost/callback",
        codeChallenge: "challenge",
      }),
      adapter.consumeAuthorizationCode("code-hash", {
        clientId: "client",
        redirectUri: "http://localhost/callback",
        codeChallenge: "challenge",
      }),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(results.filter((result) => result === null)).toHaveLength(1);
  });

  it("stores, reads, and revokes access tokens", async () => {
    const { adapter } = storage();
    await adapter.saveAccessToken({
      tokenHash: "access-hash",
      clientId: "client",
      user: { id: "user-1" },
      scopes: ["profile"],
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    });

    expect(await adapter.getAccessToken("access-hash")).toMatchObject({ clientId: "client" });
    await adapter.revokeAccessToken("access-hash");
    expect(await adapter.getAccessToken("access-hash")).toMatchObject({
      revokedAt: expect.any(Number),
    });
  });
});
