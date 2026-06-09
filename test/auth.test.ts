import { describe, it, expect, vi } from "vitest";
import { hashApiKey, safeEqualHex } from "../src/security/crypto/keys.js";

// The auth resolver logic is: look up by HMAC hash, then constant-time confirm.
// We test the matching primitives + a small resolver that takes an injected lookup fn.
import { resolveApiKey, requireRole } from "../src/middleware/auth.js";
import type { AppRequest } from "../src/types.js";
import type { Response, NextFunction } from "express";

const PEPPER = "pepper-pepper-pepper-123456";

describe("resolveApiKey", () => {
  const record = { keyId: "key_admin", keyHash: hashApiKey("RAW-ADMIN", PEPPER), role: "admin" as const, createdAt: new Date() };
  const lookup = async (hash: string) => (safeEqualHex(hash, record.keyHash) ? record : null);

  it("resolves a valid key", async () => {
    const r = await resolveApiKey("RAW-ADMIN", PEPPER, lookup);
    expect(r.keyId).toBe("key_admin");
    expect(r.role).toBe("admin");
  });
  it("throws 401 on unknown key", async () => {
    await expect(resolveApiKey("WRONG", PEPPER, lookup)).rejects.toMatchObject({ status: 401 });
  });
  it("throws 401 on empty key", async () => {
    await expect(resolveApiKey("", PEPPER, lookup)).rejects.toMatchObject({ status: 401 });
  });
});

function makeReq(role: "admin" | "client"): AppRequest {
  return { ctx: { role, keyId: "k", correlationId: "c", startTime: 0, threats: [] } } as unknown as AppRequest;
}

describe("requireRole", () => {
  it("allows admin calling requireRole('client')", () => {
    const next = vi.fn() as unknown as NextFunction;
    requireRole("client")(makeReq("admin"), {} as Response, next);
    expect(next).toHaveBeenCalledWith(); // no error arg
  });

  it("allows admin calling requireRole('admin')", () => {
    const next = vi.fn() as unknown as NextFunction;
    requireRole("admin")(makeReq("admin"), {} as Response, next);
    expect(next).toHaveBeenCalledWith();
  });

  it("blocks client calling requireRole('admin') with 403", () => {
    const next = vi.fn() as unknown as NextFunction;
    requireRole("admin")(makeReq("client"), {} as Response, next);
    expect(next).toHaveBeenCalledOnce();
    const [err] = (next as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(err).toMatchObject({ status: 403 });
  });

  it("allows client calling requireRole('client')", () => {
    const next = vi.fn() as unknown as NextFunction;
    requireRole("client")(makeReq("client"), {} as Response, next);
    expect(next).toHaveBeenCalledWith();
  });
});
