import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface Encrypted {
  iv: string;   // hex
  tag: string;  // hex
  data: string; // hex
}

/** AES-256-GCM encrypt an arbitrary JSON-serialisable value. */
export function encryptJson(value: unknown, keyHex: string): Encrypted {
  const key = Buffer.from(keyHex, "hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const json = Buffer.from(JSON.stringify(value), "utf8");
  const data = Buffer.concat([cipher.update(json), cipher.final()]);
  return { iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), data: data.toString("hex") };
}

export function decryptJson<T = unknown>(enc: Encrypted, keyHex: string): T {
  const key = Buffer.from(keyHex, "hex");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(enc.iv, "hex"));
  decipher.setAuthTag(Buffer.from(enc.tag, "hex"));
  const out = Buffer.concat([decipher.update(Buffer.from(enc.data, "hex")), decipher.final()]);
  return JSON.parse(out.toString("utf8")) as T;
}
