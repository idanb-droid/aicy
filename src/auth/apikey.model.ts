import type { Collection } from "mongodb";
import { getDb } from "../db/mongo.js";

export interface ApiKeyRecord {
  keyId: string;        // public identifier, safe to log
  keyHash: string;      // HMAC-SHA256(rawKey, pepper), hex
  role: "client" | "admin";
  rateLimitPerMin?: number;
  label?: string;
  createdAt: Date;
}

export function apiKeyCollection(): Collection<ApiKeyRecord> {
  return getDb().collection<ApiKeyRecord>("apikeys");
}

export async function ensureApiKeyIndexes(): Promise<void> {
  await apiKeyCollection().createIndex({ keyHash: 1 }, { unique: true });
}
