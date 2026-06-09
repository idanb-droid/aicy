import { describe, it, expect, beforeAll, vi } from "vitest";
import request from "supertest";

// ─── Mutable test state (mocks read these) ──────────────────────────────────
let nextRole: "client" | "admin" = "admin";
let mongoUp = true;
let redisUp = true;
let providersAny = true;
let lastQuery: { since: Date; limit: number } | null = null;

// Auth: keep the REAL requireRole (so the role guard is actually exercised),
// stub only authenticate to attach a configurable role.
vi.mock("../src/middleware/auth.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/middleware/auth.js")>();
  return {
    ...actual,
    authenticate: () => (req: any, _res: any, next: any) => {
      req.ctx.keyId = "key_test";
      req.ctx.role = nextRole;
      next();
    },
  };
});

vi.mock("../src/middleware/rateLimit.js", () => ({
  rateLimit: () => (_req: any, _res: any, next: any) => next(),
  slidingWindowAllow: async () => true,
}));

vi.mock("../src/db/mongo.js", () => ({
  pingMongo: async () => mongoUp,
  getDb: () => ({}),
  connectMongo: async () => ({}),
  closeMongo: async () => {},
}));

vi.mock("../src/db/redis.js", () => ({
  pingRedis: async () => redisUp,
  getRedis: () => ({}),
  connectRedis: () => ({}),
  closeRedis: async () => {},
}));

vi.mock("../src/providers/index.js", () => ({
  getProvider: () => ({ name: "stub", ready: () => true, chat: async () => ({ content: "ok", raw: {} }) }),
  providerReadiness: () => ({ anthropic: providersAny, openai: false, any: providersAny }),
  resetProviders: () => {},
}));

const SAMPLE = [{ ts: new Date(), keyId: "k", model: "claude-3-5-sonnet", status: "allowed" }];
vi.mock("../src/audit/audit.service.js", () => ({
  writeAudit: async () => {},
  queryAudit: async (q: { since: Date; limit: number }) => { lastQuery = q; return SAMPLE; },
}));

process.env["API_KEY_PEPPER"] = "pepper-pepper-pepper-123456";
process.env["PII_ENCRYPTION_KEY"] = "0".repeat(64);
process.env["MONGODB_URI"] = "mongodb://localhost:27017/test";
process.env["REDIS_URL"] = "redis://localhost:6379";

let app: import("express").Express;
beforeAll(async () => { app = (await import("../src/app.js")).createApp(); });

describe("GET /v1/audit — admin only", () => {
  it("rejects a client role with 403", async () => {
    nextRole = "client";
    const res = await request(app).get("/v1/audit");
    expect(res.status).toBe(403);
  });

  it("allows an admin role and returns entries", async () => {
    nextRole = "admin";
    const res = await request(app).get("/v1/audit");
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(SAMPLE.length);
    expect(Array.isArray(res.body.entries)).toBe(true);
  });

  it("parses since (epoch ms) and limit query params into the query", async () => {
    nextRole = "admin";
    lastQuery = null;
    const since = 1_700_000_000_000;
    await request(app).get(`/v1/audit?since=${since}&limit=250`);
    expect(lastQuery).not.toBeNull();
    expect(lastQuery!.limit).toBe(250);
    expect(lastQuery!.since.getTime()).toBe(since);
  });
});

describe("GET /healthz — no auth", () => {
  it("returns 200/ok when mongo, redis and a provider are up", async () => {
    mongoUp = true; redisUp = true; providersAny = true;
    const res = await request(app).get("/healthz");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body).toMatchObject({ mongo: true, redis: true });
  });

  it("returns 503/degraded when mongo is unreachable", async () => {
    mongoUp = false; redisUp = true; providersAny = true;
    const res = await request(app).get("/healthz");
    expect(res.status).toBe(503);
    expect(res.body.status).toBe("degraded");
    expect(res.body.mongo).toBe(false);
    mongoUp = true; // restore for any later use
  });

  it("returns 503 when no provider is ready", async () => {
    mongoUp = true; redisUp = true; providersAny = false;
    const res = await request(app).get("/healthz");
    expect(res.status).toBe(503);
    providersAny = true;
  });
});
