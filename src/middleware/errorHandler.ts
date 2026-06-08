import type { Request, Response, NextFunction } from "express";
import { AppError } from "../errors.js";
import { writeAudit } from "../audit/audit.service.js";
import { logger } from "../logger.js";
import type { AppRequest, AuditStatus } from "../types.js";

/** Central error handler: map error → status and guarantee one audit record. */
export async function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): Promise<void> {
  const r = req as AppRequest;
  const ctx = r.ctx;
  const appErr = err instanceof AppError ? err : new AppError(500, "internal_error", "Internal server error", "provider");
  const status: AuditStatus = appErr.status >= 500 && appErr.code === "internal_error" ? "error" : "blocked";

  if (ctx) {
    try {
      await writeAudit({
        correlationId: ctx.correlationId,
        ts: new Date(),
        keyId: ctx.keyId,
        role: ctx.role,
        model: ctx.model,
        provider: ctx.provider,
        status,
        threats: ctx.threats,
        requestHash: ctx.requestHash,
        latencyMs: Date.now() - ctx.startTime,
        blockedStage: appErr.stage,
        ...(ctx.piiMap ? { piiMap: ctx.piiMap } : {}),
        ...(status === "error" ? { error: appErr.message } : {}),
      });
    } catch (auditErr) {
      logger.error({ auditErr }, "failed to write audit record");
    }
  }

  if (appErr.status >= 500) logger.error({ err: appErr.message, code: appErr.code }, "request error");
  res.status(appErr.status).json({ error: appErr.code, message: appErr.message, ...(appErr.details ? { details: appErr.details } : {}) });
}
