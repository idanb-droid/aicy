import { describe, it, expect } from "vitest";
import RedisMock from "ioredis-mock";
import { slidingWindowAllow } from "../src/middleware/rateLimit.js";

describe("slidingWindowAllow", () => {
  it("allows up to the limit then blocks", async () => {
    const redis = new RedisMock();
    const key = "rl:test";
    const limit = 3;
    const now = 1_000_000;
    const results: boolean[] = [];
    for (let i = 0; i < 4; i++) results.push(await slidingWindowAllow(redis as any, key, limit, now + i));
    expect(results).toEqual([true, true, true, false]);
  });

  it("allows again after the window slides", async () => {
    const redis = new RedisMock();
    const key = "rl:slide";
    const now = 2_000_000;
    expect(await slidingWindowAllow(redis as any, key, 1, now)).toBe(true);
    expect(await slidingWindowAllow(redis as any, key, 1, now + 100)).toBe(false);
    expect(await slidingWindowAllow(redis as any, key, 1, now + 61_000)).toBe(true);
  });
});
