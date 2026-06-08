import { randomUUID } from "node:crypto";
import type { Redis } from "ioredis";
import type { Response, NextFunction } from "express";
import { getRedis } from "../db/redis.js";
import { loadEnv } from "../config/env.js";
import { apiKeyCollection } from "../auth/apikey.model.js";
import { RateLimitError } from "../errors.js";
import type { AppRequest } from "../types.js";

const WINDOW_MS = 60_000;

/** Returns true if the request is within the per-key sliding window. */
export async function slidingWindowAllow(redis: Redis, key: string, limit: number, now: number): Promise<boolean> {
  const member = `${now}-${randomUUID()}`;
  const pipeline = redis.multi();
  pipeline.zremrangebyscore(key, 0, now - WINDOW_MS); // drop expired
  pipeline.zadd(key, now, member);                     // record this hit
  pipeline.zcard(key);                                 // count in window
  pipeline.pexpire(key, WINDOW_MS);
  const res = await pipeline.exec();
  const count = res && res[2] && res[2][1] != null ? Number(res[2][1]) : 0;
  return count <= limit;
}

export function rateLimit() {
  return async (req: AppRequest, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const def = loadEnv().RATE_LIMIT_DEFAULT;
      const keyDoc = await apiKeyCollection().findOne({ keyId: req.ctx.keyId }, { projection: { rateLimitPerMin: 1 } });
      const limit = keyDoc?.rateLimitPerMin ?? def;
      const allowed = await slidingWindowAllow(getRedis(), `rl:${req.ctx.keyId}`, limit, Date.now());
      if (!allowed) { next(RateLimitError()); return; }
      next();
    } catch (err) {
      next(err);
    }
  };
}
