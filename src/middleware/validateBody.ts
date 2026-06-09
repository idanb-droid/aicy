import { z } from "zod";
import type { Response, NextFunction } from "express";
import { ValidationError } from "../errors.js";
import { sha256 } from "./correlation.js";
import type { AppRequest } from "../types.js";

const ChatBodySchema = z.object({
  model: z.enum(["claude-3-5-sonnet", "gpt-4o"]),
  messages: z.array(z.object({
    role: z.enum(["user", "assistant", "system"]),
    content: z.string().min(1),
  })).min(1),
  max_tokens: z.number().int().positive().max(4096).default(1024),
});

/** Validate the /v1/chat body and capture the original request hash (pre-redaction). */
export function validateChatBody() {
  return (req: AppRequest, _res: Response, next: NextFunction): void => {
    const parsed = ChatBodySchema.safeParse(req.body);
    if (!parsed.success) { next(ValidationError(parsed.error.flatten())); return; }
    req.body = parsed.data;
    req.ctx.model = parsed.data.model;
    req.ctx.requestHash = sha256(JSON.stringify(parsed.data));
    next();
  };
}
