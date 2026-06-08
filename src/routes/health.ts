import { Router } from "express";
import { pingMongo } from "../db/mongo.js";
import { pingRedis } from "../db/redis.js";
import { providerReadiness } from "../providers/index.js";

export const healthRouter = Router();

healthRouter.get("/healthz", async (_req, res) => {
  const [mongo, redis] = await Promise.all([pingMongo(), pingRedis()]);
  const providers = providerReadiness();
  const ok = mongo && redis && providers.any;
  res.status(ok ? 200 : 503).json({
    status: ok ? "ok" : "degraded",
    mongo, redis,
    providers: { anthropic: providers.anthropic, openai: providers.openai },
  });
});
