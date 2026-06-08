import express, { type RequestHandler } from "express";
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

// Cast helper: middleware typed for AppRequest (subtype of Request) needs a cast for app.use.
const mw = (fn: RequestHandler): RequestHandler => fn;

export function createApp() {
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(pinoHttp({ logger }));
  app.use(mw(correlation() as unknown as RequestHandler));

  app.use(healthRouter); // no auth

  // Route modules define "/" internally; the path prefix here is the full mount path.
  app.use("/v1/chat",
    mw(authenticate() as unknown as RequestHandler),
    mw(rateLimit() as unknown as RequestHandler),
    mw(validateChatBody() as unknown as RequestHandler),
    mw(injectionGuard() as unknown as RequestHandler),
    mw(piiRedaction() as unknown as RequestHandler),
    chatRouter,
  );
  app.use("/v1/audit",
    mw(authenticate() as unknown as RequestHandler),
    mw(requireRole("admin") as unknown as RequestHandler),
    auditRouter,
  );

  app.use(errorHandler);
  return app;
}
