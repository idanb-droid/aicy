import type { Response, NextFunction } from "express";
import { detectInjectionInMessages } from "../security/injection/detector.js";
import { InjectionError } from "../errors.js";
import type { AppRequest, ChatBody } from "../types.js";

/** Reject any request whose messages contain a detected injection. */
export function injectionGuard() {
  return (req: AppRequest, _res: Response, next: NextFunction): void => {
    const body = req.body as ChatBody;
    const result = detectInjectionInMessages(body.messages);
    if (result.matched) {
      req.ctx.threats = result.rules;
      next(InjectionError({ rules: result.rules }));
      return;
    }
    next();
  };
}
