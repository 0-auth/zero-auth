import { describe, expect, it } from "vitest";
import {
  createRedisRevocationStore,
  type RedisClient,
  type RedisPipeline,
} from "../../src/index.js";

class FakeRedis implements RedisClient {
  readonly revoked = new Set<string>();
  readonly families = new Map<string, Set<string>>();
  failPipeline = false;

  async set(key: string, _value: string, ...args: Array<string | number>): Promise<string | null> {
    if (args.includes("NX") && this.revoked.has(key)) return null;
    this.revoked.add(key);
    return "OK";
  }

  async exists(key: string): Promise<number> {
    return this.revoked.has(key) ? 1 : 0;
  }

  async sismember(key: string, member: string): Promise<number> {
    return this.families.get(key)?.has(member) ? 1 : 0;
  }

  async smembers(key: string): Promise<string[]> {
    return [...(this.families.get(key) ?? [])];
  }

  async eval(_script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown> {
    const keys = args.slice(0, numKeys).map(String);
    const values = args.slice(numKeys).map(String);
    const familyKey = keys[0];
    const jti = values[0];
    const compromisedMember = values[2];
    if (!familyKey || !jti || !compromisedMember) throw new Error("missing Redis script values");

    if (this.families.get(familyKey)?.has(compromisedMember)) return 0;
    this.addToFamily(familyKey, jti);
    return 1;
  }

  pipeline(): RedisPipeline {
    return new FakePipeline(this);
  }

  addToFamily(key: string, jti: string): void {
    const members = this.families.get(key) ?? new Set<string>();
    members.add(jti);
    this.families.set(key, members);
  }
}

class FakePipeline implements RedisPipeline {
  constructor(private readonly redis: FakeRedis) {}

  sadd(key: string, member: string): RedisPipeline {
    this.redis.addToFamily(key, member);
    return this;
  }

  expire(_key: string, _seconds: number): RedisPipeline {
    return this;
  }

  set(key: string, _value: string, ..._args: Array<string | number>): RedisPipeline {
    this.redis.revoked.add(key);
    return this;
  }

  async exec(): Promise<ReadonlyArray<readonly [Error | null, unknown]> | null> {
    if (this.redis.failPipeline) return [[new Error("pipeline failed"), null]];
    return [[null, "OK"]];
  }
}

describe("createRedisRevocationStore", () => {
  it("atomically consumes once and revokes a tracked family", async () => {
    const redis = new FakeRedis();
    const store = createRedisRevocationStore(redis, 60);
    const context = { userId: "user-1", familyId: "family-1" };

    expect(await store.consume("old-jti", context)).toBe(true);
    expect(await store.consume("old-jti", context)).toBe(false);
    await store.register("new-jti", context);

    expect(await store.isRevoked("new-jti")).toBe(false);
    await store.revokeFamily("family-1");
    expect(await store.isRevoked("old-jti")).toBe(true);
    expect(await store.isRevoked("new-jti")).toBe(true);
  });

  it("rejects registrations after a family is marked compromised", async () => {
    const redis = new FakeRedis();
    const store = createRedisRevocationStore(redis);
    const context = { userId: "user-1", familyId: "family-1" };

    await store.revokeFamily("family-1");
    expect(await store.consume("after-reuse-jti", context)).toBe(false);

    await expect(store.register("late-jti", context)).rejects.toThrow(
      "family has already been revoked"
    );
  });

  it("allows only one concurrent consume for the same jti", async () => {
    const redis = new FakeRedis();
    const store = createRedisRevocationStore(redis);
    const attempts = await Promise.all(
      Array.from({ length: 32 }, () =>
        Promise.resolve(store.consume("same-jti", { userId: "user-1", familyId: "family-1" }))
      )
    );

    expect(attempts.filter(Boolean)).toHaveLength(1);
  });

  it("fails when Redis reports a pipeline error", async () => {
    const redis = new FakeRedis();
    redis.failPipeline = true;
    const store = createRedisRevocationStore(redis);

    await expect(store.revoke("jti", "family-1")).rejects.toThrow("pipeline failed");
  });

  it("rejects an invalid TTL", () => {
    expect(() => createRedisRevocationStore(new FakeRedis(), 0)).toThrow(
      "ttlSeconds must be a positive integer"
    );
  });
});
