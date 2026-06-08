import { Redis } from "ioredis";

let redis: Redis | null = null;

export function connectRedis(url: string): Redis {
  if (redis) return redis;
  redis = new Redis(url, { maxRetriesPerRequest: 2, lazyConnect: false });
  return redis;
}

export function getRedis(): Redis {
  if (!redis) throw new Error("Redis not connected");
  return redis;
}

export async function pingRedis(): Promise<boolean> {
  try {
    if (!redis) return false;
    return (await redis.ping()) === "PONG";
  } catch {
    return false;
  }
}

export async function closeRedis(): Promise<void> {
  await redis?.quit();
  redis = null;
}
