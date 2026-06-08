import { auditCollection, type AuditRecord } from "./audit.model.js";

export async function writeAudit(record: AuditRecord): Promise<void> {
  await auditCollection().insertOne(record);
}

export interface AuditQuery { since: Date; limit: number; }

export async function queryAudit({ since, limit }: AuditQuery): Promise<AuditRecord[]> {
  const capped = Math.min(Math.max(limit, 1), 500);
  return auditCollection()
    .find({ ts: { $gte: since } }, { projection: { _id: 0 } })
    .sort({ ts: -1 })
    .limit(capped)
    .toArray();
}
