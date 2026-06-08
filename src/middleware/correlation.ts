import { randomUUID, createHash } from "node:crypto";
import type { Response, NextFunction } from "express";
import type { AppRequest, RequestContext } from "../types.js";

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Initialise per-request context. Must run first in the chain. */
export function correlation() {
  return (req: AppRequest, res: Response, next: NextFunction): void => {
    const ctx: RequestContext = {
      correlationId: req.header("x-correlation-id") ?? randomUUID(),
      startTime: Date.now(),
      keyId: "unknown",
      role: "unknown",
      threats: [],
    };
    req.ctx = ctx;
    res.setHeader("x-correlation-id", ctx.correlationId);
    next();
  };
}
