import type { RefreshTokenContext } from "../types/auth.js";

// Simple in-memory revocation store for demo and testing purposes.
// Not suitable for production — use Redis or another durable store for real deployments.

export function createInMemoryRevocationStore(ttlSeconds = 60 * 60 * 24) {
  const map = new Map<string, number>(); // jti -> expiryTimestampMs
  const families = new Map<string, Set<string>>(); // familyId -> jtis

  function nowMs() {
    return Date.now();
  }

  function trackFamily(jti: string, familyId?: string): void {
    if (!familyId) return;
    let members = families.get(familyId);
    if (!members) {
      members = new Set();
      families.set(familyId, members);
    }
    members.add(jti);
  }

  return {
    /** Atomically consume a jti; returns false when it was already consumed. */
    async consume(jti: string, family?: string | RefreshTokenContext): Promise<boolean> {
      const familyId = resolveFamilyId(family);
      const exp = map.get(jti);
      if (exp !== undefined) {
        if (exp >= nowMs()) return false;
        map.delete(jti);
      }

      map.set(jti, nowMs() + ttlSeconds * 1000);
      trackFamily(jti, familyId);
      return true;
    },

    /** Mark a jti as revoked; optionally associate it with a family. */
    async revoke(jti: string, familyId?: string): Promise<void> {
      const expiry = nowMs() + ttlSeconds * 1000;
      map.set(jti, expiry);
      trackFamily(jti, familyId);
    },

    /** Track a live jti under a family without revoking it (for family kill on reuse). */
    async register(jti: string, family?: string | RefreshTokenContext): Promise<void> {
      const familyId = resolveFamilyId(family);
      trackFamily(jti, familyId);
    },

    async isRevoked(jti: string): Promise<boolean> {
      const exp = map.get(jti);
      if (!exp) return false;
      if (exp < nowMs()) {
        map.delete(jti);
        return false;
      }
      return true;
    },

    /** Revoke every jti known for a family (reuse / theft response). */
    async revokeFamily(familyId: string): Promise<void> {
      const members = families.get(familyId);
      if (!members) return;
      const expiry = nowMs() + ttlSeconds * 1000;
      for (const jti of members) {
        map.set(jti, expiry);
      }
    },

    // For tests and debugging
    _size(): number {
      return map.size;
    },

    _familySize(familyId: string): number {
      return families.get(familyId)?.size ?? 0;
    },
  };
}

function resolveFamilyId(family?: string | RefreshTokenContext): string | undefined {
  return typeof family === "string" ? family : family?.familyId;
}
