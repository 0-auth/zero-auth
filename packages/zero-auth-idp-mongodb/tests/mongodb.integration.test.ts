import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";
import { MongoClient } from "mongodb";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMongoOAuthStorage, type MongoOAuthStorage } from "../src/index.js";

const connectionString = process.env["MONGODB_URI"];
const integration = connectionString ? describe : describe.skip;

integration("MongoOAuthStorage with MongoDB", () => {
  let client: MongoClient;
  let storage: MongoOAuthStorage;
  let databaseName: string;

  beforeAll(async () => {
    client = new MongoClient(connectionString!, { serverSelectionTimeoutMS: 5000 });
    await client.connect();
    databaseName = `zero_auth_idp_test_${randomUUID().replaceAll("-", "")}`;
    storage = createMongoOAuthStorage(client.db(databaseName), {
      collectionPrefix: "integration",
    });
    await storage.ensureIndexes();
  });

  afterAll(async () => {
    try {
      if (databaseName?.startsWith("zero_auth_idp_test_")) {
        await client.db(databaseName).dropDatabase();
      }
    } finally {
      await client?.close();
    }
  });

  it("creates TTL indexes and persists records across adapter instances", async () => {
    const user = { id: "mongo-user", email: "mongo@example.com" };
    await storage.saveSession({
      tokenHash: "session-hash",
      user,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
    });

    const secondAdapter = createMongoOAuthStorage(client.db(databaseName), {
      collectionPrefix: "integration",
    });
    expect(await secondAdapter.getSession("session-hash")).toEqual({
      user,
      tokenHash: "session-hash",
      createdAt: expect.any(Number),
      expiresAt: expect.any(Number),
    });

    const indexes = await client.db(databaseName).collection("integration_sessions").indexes();
    expect(indexes.some((index) => index.expireAfterSeconds === 0)).toBe(true);
  });

  it("consumes one authorization code under concurrent exchange", async () => {
    await storage.saveAuthorizationCode({
      codeHash: "integration-code",
      clientId: "client",
      user: { id: "mongo-user" },
      redirectUri: "http://localhost/callback",
      scopes: ["profile"],
      codeChallenge: "challenge",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    });

    const expected = {
      clientId: "client",
      redirectUri: "http://localhost/callback",
      codeChallenge: "challenge",
    };
    for (const invalid of [
      { ...expected, clientId: "wrong-client" },
      { ...expected, redirectUri: "http://localhost/other" },
      { ...expected, codeChallenge: "wrong-challenge" },
    ]) {
      expect(await storage.consumeAuthorizationCode("integration-code", invalid)).toBeNull();
    }
    const results = await Promise.all([
      createMongoOAuthStorage(client.db(databaseName), {
        collectionPrefix: "integration",
      }).consumeAuthorizationCode("integration-code", expected),
      storage.consumeAuthorizationCode("integration-code", expected),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(results.filter((result) => result === null)).toHaveLength(1);
  });

  it("stores BSON dates and MongoDB actually deletes expired records in all four collections", async () => {
    const live = {
      clientId: "client",
      user: { id: "ttl-user" },
      scopes: ["profile"],
      redirectUri: "http://localhost/callback",
      codeChallenge: "challenge",
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
    };
    const expired = { ...live, expiresAt: Date.now() - 1000 };
    for (const [key, record] of [
      ["ttl-expired", expired],
      ["ttl-live", live],
    ] as const) {
      await storage.saveSession({ ...record, tokenHash: key });
      await storage.saveTransaction({ ...record, id: key });
      await storage.saveAuthorizationCode({ ...record, codeHash: key });
      await storage.saveAccessToken({ ...record, tokenHash: key });
    }
    const collections = ["sessions", "transactions", "authorization_codes", "access_tokens"].map(
      (suffix) => client.db(databaseName).collection(`integration_${suffix}`)
    );
    for (const collection of collections) {
      const record =
        (await collection.findOne({ tokenHash: "ttl-live" })) ??
        (await collection.findOne({ id: "ttl-live" })) ??
        (await collection.findOne({ codeHash: "ttl-live" }));
      expect(record?.expiresAt).toBeInstanceOf(Date);
      expect(record?.expiresAt.getTime()).toBe(live.expiresAt);
      expect(await collection.indexes()).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ key: { expiresAt: 1 }, expireAfterSeconds: 0 }),
        ])
      );
    }
    // Expiration checks must reject immediately, before Mongo's background TTL pass.
    expect(await storage.getSession("ttl-expired")).toBeNull();
    expect(await storage.getTransaction("ttl-expired")).toBeNull();
    expect(await storage.consumeAuthorizationCode("ttl-expired", live)).toBeNull();
    const deadline = Date.now() + 90_000;
    while (true) {
      const counts = await Promise.all(
        collections.map((collection) =>
          collection.countDocuments({ expiresAt: { $lte: new Date() } })
        )
      );
      if (counts.every((count) => count === 0)) break;
      if (Date.now() >= deadline)
        throw new Error("MongoDB did not remove expired records within 90 seconds");
      await setTimeout(1000);
    }
    expect((await storage.getSession("ttl-live"))?.expiresAt).toBe(live.expiresAt);
  }, 100_000);

  it("persists access-token and session revocation after reconnecting", async () => {
    await storage.saveAccessToken({
      tokenHash: "revoke",
      clientId: "client",
      user: { id: "user" },
      scopes: ["profile"],
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    });
    await storage.revokeAccessToken("revoke");
    await storage.revokeSession("session-hash");
    const connection = new MongoClient(connectionString!);
    try {
      await connection.connect();
      const reconnected = createMongoOAuthStorage(connection.db(databaseName), {
        collectionPrefix: "integration",
      });
      expect(await reconnected.getAccessToken("revoke")).toMatchObject({
        revokedAt: expect.any(Number),
      });
      expect(await reconnected.getSession("session-hash")).toBeNull();
    } finally {
      await connection.close();
    }
  });
});
