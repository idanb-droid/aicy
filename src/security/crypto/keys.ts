import { createHmac, timingSafeEqual } from "node:crypto";

/** Keyed hash of a high-entropy API key. Indexable + constant-time comparable. */
export function hashApiKey(rawKey: string, pepper: string): string {
  return createHmac("sha256", pepper).update(rawKey).digest("hex");
}

/** Constant-time comparison of two hex strings. Length mismatch => false. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ab.length !== bb.length || ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}
