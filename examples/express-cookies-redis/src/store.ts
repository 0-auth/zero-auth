/**
 * Redis-backed Revocation Store for @0-auth/zero-auth
 *
 * Implements the same interface as `createInMemoryRevocationStore` but uses
 * Redis SETs for durability, horizontal scaling, and automatic TTL cleanup.
 *
 * Keys used:
 *   revoked:<jti>              — EXISTS check for revocation (with TTL)
 *   family:<familyId>          — SET of jtis belonging to this token family
 */

import { Redis } from "ioredis";

export function createRedisRevocationStore(redis: Redis, ttlSeconds = 60 * 60 * 24 * 8) {
  // TTL slightly longer than refresh token lifetime to cover clock skew.

  return {
    /**
     * Atomically consume a jti. Redis SET NX makes this safe across instances.
     */
    async consume(jti: string, familyId?: string): Promise<boolean> {
      const result = await redis.set(`revoked:${jti}`, "1", "EX", ttlSeconds, "NX");
      if (result !== "OK") return false;

      if (familyId) {
        const pipeline = redis.pipeline();
        pipeline.sadd(`family:${familyId}`, jti);
        pipeline.expire(`family:${familyId}`, ttlSeconds);
        await pipeline.exec();
      }

      return true;
    },

    /**
     * Mark a jti as revoked; optionally track it under a family.
     */
    async revoke(jti: string, familyId?: string): Promise<void> {
      const pipeline = redis.pipeline();
      pipeline.set(`revoked:${jti}`, "1", "EX", ttlSeconds);

      if (familyId) {
        pipeline.sadd(`family:${familyId}`, jti);
        pipeline.expire(`family:${familyId}`, ttlSeconds);
      }

      await pipeline.exec();
    },

    /**
     * Track a live jti under a family without revoking it.
     * Called after a new refresh token is issued so we know which jtis
     * belong to the family (needed for family-wide revocation on reuse).
     */
    async register(jti: string, familyId?: string): Promise<void> {
      if (!familyId) return;

      const pipeline = redis.pipeline();
      pipeline.sadd(`family:${familyId}`, jti);
      pipeline.expire(`family:${familyId}`, ttlSeconds);
      await pipeline.exec();
    },

    /**
     * Check if a jti has been revoked.
     */
    async isRevoked(jti: string): Promise<boolean> {
      const result = await redis.exists(`revoked:${jti}`);
      return result === 1;
    },

    /**
     * Revoke every jti known for a family (reuse / theft response).
     * Called by `onRefreshReuse` to kill all tokens in a compromised family.
     */
    async revokeFamily(familyId: string): Promise<void> {
      const members = await redis.smembers(`family:${familyId}`);
      if (members.length === 0) return;

      const pipeline = redis.pipeline();
      for (const jti of members) {
        pipeline.set(`revoked:${jti}`, "1", "EX", ttlSeconds);
      }
      await pipeline.exec();
    },
  };
}
