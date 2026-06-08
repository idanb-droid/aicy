import type { Collection } from "mongodb";
import { getDb } from "../db/mongo.js";
import type { AuditStatus } from "../types.js";
import type { Encrypted } from "../security/crypto/cipher.js";
import type { BlockedStage } from "../errors.js";

export interface AuditRecord {
  correlationId: string;
  ts: Date;
  keyId: string;
  role: string;
  model?: string;
  provider?: string;
  status: AuditStatus;
  threats: { id: string; category: string }[];
  requestHash?: string;
  responseHash?: string;
  latencyMs: number;
  blockedStage?: BlockedStage;
  piiMap?: Encrypted;
  error?: string;
}

export function auditCollection(): Collection<AuditRecord> {
  return getDb().collection<AuditRecord>("audit");
}

export async function ensureAuditIndexes(): Promise<void> {
  await auditCollection().createIndex({ ts: -1 });
}
