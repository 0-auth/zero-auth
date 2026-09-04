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
  sismember(key: string, member: string): Promise<number>;
  smembers(key: string): Promise<string[]>;
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown>;
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
 * instances. Family compromise is marked before member revocation, and late
 * family registrations are rejected atomically. The package does not depend
 * on a Redis client; install and own the client in the application.
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
  const compromisedMember = "__zero_auth_family_compromised__";

  const registerScript = [
    'if redis.call("SISMEMBER", KEYS[1], ARGV[3]) == 1 then return 0 end',
    'redis.call("SADD", KEYS[1], ARGV[1])',
    'redis.call("EXPIRE", KEYS[1], ARGV[2])',
    "return 1",
  ].join("\n");

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
      if (
        context?.familyId &&
        (await redis.sismember(familyKey(context.familyId), compromisedMember)) === 1
      ) {
        return false;
      }

      const result = await redis.set(revokedKey(jti), "1", "EX", ttlSeconds, "NX");
      if (result !== "OK") return false;

      await trackFamily(jti, context?.familyId);
      return true;
    },

    async register(jti: string, context: RefreshTokenContext): Promise<void> {
      if (!context.familyId) return;

      const result = await redis.eval(
        registerScript,
        1,
        familyKey(context.familyId),
        jti,
        ttlSeconds,
        compromisedMember
      );
      if (Number(result) !== 1) {
        throw new Error("Redis refresh token family has already been revoked.");
      }
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
      const markerPipeline = redis.pipeline() as RedisPipeline;
      markerPipeline.sadd(familyKey(familyId), compromisedMember);
      markerPipeline.expire(familyKey(familyId), ttlSeconds);
      await execute(markerPipeline);

      const members = (await redis.smembers(familyKey(familyId))).filter(
        (member) => member !== compromisedMember
      );
      if (members.length === 0) return;

      const pipeline = redis.pipeline() as RedisPipeline;
      for (const jti of members) {
        pipeline.set(revokedKey(jti), "1", "EX", ttlSeconds);
      }
      await execute(pipeline);
    },
  };
}
