import { loadEnv } from "./config/env.js";
import { logger } from "./logger.js";
import { connectMongo, closeMongo } from "./db/mongo.js";
import { connectRedis, closeRedis } from "./db/redis.js";
import { ensureAuditIndexes } from "./audit/audit.model.js";
import { ensureApiKeyIndexes } from "./auth/apikey.model.js";
import { createApp } from "./app.js";

async function main() {
  const env = loadEnv();
  await connectMongo(env.MONGODB_URI);
  connectRedis(env.REDIS_URL);
  await ensureAuditIndexes();
  await ensureApiKeyIndexes();

  const app = createApp();
  const server = app.listen(env.PORT, () => logger.info(`SecureLLM Gateway listening on :${env.PORT}`));

  const shutdown = async () => {
    server.close();
    await closeMongo();
    await closeRedis();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => { logger.error({ err: String(err) }, "fatal startup error"); process.exit(1); });
