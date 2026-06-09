import { describe, it, expect, vi, beforeEach } from "vitest";

// Capture the args queryAudit forwards to the Mongo collection, without a DB.
const calls: Record<string, unknown> = {};
const chain = {
  sort(s: unknown) { calls["sort"] = s; return chain; },
  limit(n: number) { calls["limit"] = n; return chain; },
  async toArray() { return [{ ts: new Date(), keyId: "k" }]; },
};
vi.mock("../src/audit/audit.model.js", () => ({
  auditCollection: () => ({
    find(filter: unknown, opts: unknown) { calls["filter"] = filter; calls["opts"] = opts; return chain; },
  }),
}));

import { queryAudit } from "../src/audit/audit.service.js";

describe("queryAudit — limit clamp + since filter", () => {
  beforeEach(() => { for (const k of Object.keys(calls)) delete calls[k]; });

  it("clamps an over-large limit to 500", async () => {
    await queryAudit({ since: new Date(0), limit: 100_000 });
    expect(calls["limit"]).toBe(500);
  });

  it("clamps a non-positive limit up to 1", async () => {
    await queryAudit({ since: new Date(0), limit: 0 });
    expect(calls["limit"]).toBe(1);
  });

  it("passes a $gte since filter, newest-first sort, and _id projection", async () => {
    const since = new Date("2026-01-01T00:00:00.000Z");
    await queryAudit({ since, limit: 50 });
    expect(calls["filter"]).toEqual({ ts: { $gte: since } });
    expect(calls["limit"]).toBe(50);
    expect(calls["sort"]).toEqual({ ts: -1 });
    expect(calls["opts"]).toEqual({ projection: { _id: 0 } });
  });
});
