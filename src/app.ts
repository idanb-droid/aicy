import express, { type Response, type NextFunction, type RequestHandler } from "express";
import { pinoHttp } from "pino-http";
import { logger } from "./logger.js";
import { correlation } from "./middleware/correlation.js";
import { authenticate, requireRole } from "./middleware/auth.js";
import { rateLimit } from "./middleware/rateLimit.js";
import { validateChatBody } from "./middleware/validateBody.js";
import { injectionGuard } from "./middleware/injection.js";
import { piiRedaction } from "./middleware/pii.js";
import { chatRouter } from "./routes/chat.js";
import { auditRouter } from "./routes/audit.js";
import { healthRouter } from "./routes/health.js";
import { errorHandler } from "./middleware/errorHandler.js";
import type { AppRequest } from "./types.js";

type AppMW = (req: AppRequest, res: Response, next: NextFunction) => void | Promise<void>;
const mw = (fn: AppMW): RequestHandler => fn as unknown as RequestHandler;

export function createApp() {
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(pinoHttp({ logger }));
  app.use(mw(correlation()));

  app.use(healthRouter); // no auth

  // Route modules define "/" internally; the path prefix here is the full mount path.
  app.use("/v1/chat",
    mw(authenticate()),
    mw(rateLimit()),
    mw(validateChatBody()),
    mw(injectionGuard()),
    mw(piiRedaction()),
    chatRouter,
  );
  app.use("/v1/audit",
    mw(authenticate()),
    mw(requireRole("admin")),
    auditRouter,
  );

  app.use(errorHandler);
  return app;
}
