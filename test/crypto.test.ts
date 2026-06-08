import { describe, it, expect } from "vitest";
import { hashApiKey, safeEqualHex } from "../src/security/crypto/keys.js";
import { encryptJson, decryptJson } from "../src/security/crypto/cipher.js";

const PEPPER = "test-pepper-0123456789abcdef";
const KEY = "0".repeat(64); // 32 bytes hex

describe("keys", () => {
  it("hashApiKey is deterministic and hex", () => {
    const a = hashApiKey("secret-key", PEPPER);
    const b = hashApiKey("secret-key", PEPPER);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
  it("different keys produce different hashes", () => {
    expect(hashApiKey("a", PEPPER)).not.toBe(hashApiKey("b", PEPPER));
  });
  it("safeEqualHex returns true for equal, false for unequal/length-mismatch", () => {
    const h = hashApiKey("k", PEPPER);
    expect(safeEqualHex(h, h)).toBe(true);
    expect(safeEqualHex(h, hashApiKey("other", PEPPER))).toBe(false);
    expect(safeEqualHex(h, "abc")).toBe(false);
  });
});

describe("cipher", () => {
  it("round-trips an object", () => {
    const payload = { "[EMAIL_1]": "a@b.com", "[ISR_ID_1]": "123456782" };
    const enc = encryptJson(payload, KEY);
    expect(enc.iv).toMatch(/^[0-9a-f]+$/);
    expect(enc.data).not.toContain("a@b.com");
    expect(decryptJson(enc, KEY)).toEqual(payload);
  });
  it("tampered ciphertext fails to decrypt", () => {
    const enc = encryptJson({ x: 1 }, KEY);
    expect(() => decryptJson({ ...enc, data: enc.data.replace(/.$/, "0") }, KEY)).toThrow();
  });
  it("16-byte (32-hex) key throws on encrypt", () => {
    const shortKey = "0".repeat(32); // 16 bytes, not 32
    expect(() => encryptJson({ x: 1 }, shortKey)).toThrow(TypeError);
    expect(() => encryptJson({ x: 1 }, shortKey)).toThrow("cipher key must be 32 bytes (64 hex chars)");
  });
  it("16-byte (32-hex) key throws on decrypt", () => {
    const shortKey = "0".repeat(32); // 16 bytes, not 32
    const fakeEnc = { iv: "0".repeat(24), tag: "0".repeat(32), data: "00" };
    expect(() => decryptJson(fakeEnc, shortKey)).toThrow(TypeError);
    expect(() => decryptJson(fakeEnc, shortKey)).toThrow("cipher key must be 32 bytes (64 hex chars)");
  });
});
