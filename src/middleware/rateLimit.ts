import { randomUUID } from "node:crypto";
import type { Redis } from "ioredis";
import type { Response, NextFunction } from "express";
import { getRedis } from "../db/redis.js";
import { loadEnv } from "../config/env.js";
import { RateLimitError } from "../errors.js";
import type { AppRequest } from "../types.js";

const WINDOW_MS = 60_000;

/** Returns true if the request is within the per-key sliding window.
 *  Throws if the Redis pipeline returns a null/error result (fail-closed). */
export async function slidingWindowAllow(redis: Redis, key: string, limit: number, now: number): Promise<boolean> {
  const member = `${now}-${randomUUID()}`;
  const pipeline = redis.multi();
  pipeline.zremrangebyscore(key, "-inf", now - WINDOW_MS); // drop expired
  pipeline.zadd(key, now, member);                          // record this hit
  pipeline.zcard(key);                                      // count in window
  pipeline.pexpire(key, WINDOW_MS);
  const res = await pipeline.exec();
  if (!res || !res[2] || res[2][0] != null || res[2][1] == null) {
    throw new Error("rate limiter: redis pipeline failed");
  }
  const count = Number(res[2][1]);
  return count <= limit;
}

export function rateLimit() {
  return async (req: AppRequest, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const limit = req.ctx.rateLimitPerMin ?? loadEnv().RATE_LIMIT_DEFAULT;
      const allowed = await slidingWindowAllow(getRedis(), `rl:${req.ctx.keyId}`, limit, Date.now());
      if (!allowed) { next(RateLimitError()); return; }
      next();
    } catch (err) {
      next(err);
    }
  };
}
