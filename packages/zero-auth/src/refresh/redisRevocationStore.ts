import type { RefreshTokenContext, RefreshTokenStore } from "../types/auth.js";

/** The ioredis-compatible pipeline methods used by the Redis store. */
export interface RedisPipeline {
  sadd(key: string, member: string): RedisPipeline;
  expire(key: string, seconds: number): RedisPipeline;
  set(key: string, value: string, ...args: Array<string | number>): RedisPipeline;
  exec(): Promise<ReadonlyArray<readonly [Error | null, unknown]> | null>;
}

/** The ioredis-compatible client surface required by the Redis store. */
export interface RedisClient {
  set(
    key: string,
    value: string,
    secondsToken: "EX",
    seconds: number,
    nx: "NX"
  ): Promise<"OK" | null>;
  exists(key: string): Promise<number>;
  smembers(key: string): Promise<string[]>;
  pipeline(): unknown;
}

export interface RedisRevocationStore extends RefreshTokenStore {
  /** Mark a jti as revoked; optionally associate it with a token family. */
  revoke(jti: string, familyId?: string): Promise<void>;
  /** Check whether a jti is currently revoked. */
  isRevoked(jti: string): Promise<boolean>;
  /** Revoke every known jti in a token family. */
  revokeFamily(familyId: string): Promise<void>;
}

/**
 * Creates a Redis-backed refresh-token store for ioredis-compatible clients.
 *
 * The `NX` write makes refresh-token consumption atomic across application
 * instances. The package does not depend on a Redis client; install and own
 * the client in the application.
 */
export function createRedisRevocationStore(
  redis: RedisClient,
  ttlSeconds = 60 * 60 * 24 * 8
): RedisRevocationStore {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new RangeError("ttlSeconds must be a positive integer.");
  }

  const revokedKey = (jti: string) => `revoked:${jti}`;
  const familyKey = (familyId: string) => `family:${familyId}`;

  async function execute(pipeline: RedisPipeline): Promise<void> {
    const results = await pipeline.exec();
    if (results === null) throw new Error("Redis pipeline returned no result.");

    for (const result of results) {
      if (result[0]) throw result[0];
    }
  }

  async function trackFamily(jti: string, familyId?: string): Promise<void> {
    if (!familyId) return;

    const pipeline = redis.pipeline() as RedisPipeline;
    pipeline.sadd(familyKey(familyId), jti);
    pipeline.expire(familyKey(familyId), ttlSeconds);
    await execute(pipeline);
  }

  return {
    async consume(jti: string, context?: RefreshTokenContext): Promise<boolean> {
      const result = await redis.set(revokedKey(jti), "1", "EX", ttlSeconds, "NX");
      if (result !== "OK") return false;

      await trackFamily(jti, context?.familyId);
      return true;
    },

    async register(jti: string, context: RefreshTokenContext): Promise<void> {
      await trackFamily(jti, context.familyId);
    },

    async revoke(jti: string, familyId?: string): Promise<void> {
      const pipeline = redis.pipeline() as RedisPipeline;
      pipeline.set(revokedKey(jti), "1", "EX", ttlSeconds);
      if (familyId) {
        pipeline.sadd(familyKey(familyId), jti);
        pipeline.expire(familyKey(familyId), ttlSeconds);
      }
      await execute(pipeline);
    },

    async isRevoked(jti: string): Promise<boolean> {
      return (await redis.exists(revokedKey(jti))) === 1;
    },

    async revokeFamily(familyId: string): Promise<void> {
      const members = await redis.smembers(familyKey(familyId));
      if (members.length === 0) return;

      const pipeline = redis.pipeline() as RedisPipeline;
      for (const jti of members) {
        pipeline.set(revokedKey(jti), "1", "EX", ttlSeconds);
      }
      await execute(pipeline);
    },
  };
}
