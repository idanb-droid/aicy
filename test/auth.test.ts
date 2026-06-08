import { describe, it, expect } from "vitest";
import { hashApiKey, safeEqualHex } from "../src/security/crypto/keys.js";

// The auth resolver logic is: look up by HMAC hash, then constant-time confirm.
// We test the matching primitives + a small resolver that takes an injected lookup fn.
import { resolveApiKey } from "../src/middleware/auth.js";

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
