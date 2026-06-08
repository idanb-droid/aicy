import { randomBytes } from "node:crypto";
import { loadEnv } from "../config/env.js";
import { connectMongo, closeMongo } from "../db/mongo.js";
import { hashApiKey } from "../security/crypto/keys.js";
import { apiKeyCollection, ensureApiKeyIndexes, type ApiKeyRecord } from "../auth/apikey.model.js";

function genKey(role: "client" | "admin"): string {
  return `sllm_${role}_${randomBytes(24).toString("hex")}`;
}

async function main() {
  const env = loadEnv();
  await connectMongo(env.MONGODB_URI);
  await ensureApiKeyIndexes();

  const col = apiKeyCollection();
  const created: { role: string; rawKey: string; keyId: string }[] = [];

  for (const role of ["client", "admin"] as const) {
    const rawKey = genKey(role);
    const record: ApiKeyRecord = {
      keyId: `key_${role}_${randomBytes(4).toString("hex")}`,
      keyHash: hashApiKey(rawKey, env.API_KEY_PEPPER),
      role,
      label: `seed ${role}`,
      createdAt: new Date(),
    };
    await col.insertOne(record);
    created.push({ role, rawKey, keyId: record.keyId });
  }

  console.log("\n=== Seeded API keys (store securely; shown ONCE) ===");
  for (const c of created) console.log(`${c.role.padEnd(6)} keyId=${c.keyId}  x-api-key: ${c.rawKey}`);
  console.log("====================================================\n");

  await closeMongo();
}

main().catch((err) => { console.error(err); process.exit(1); });
