import type { Response, NextFunction } from "express";
import { redactPii } from "../security/pii/redactor.js";
import { encryptJson } from "../security/crypto/cipher.js";
import { loadEnv } from "../config/env.js";
import type { AppRequest, ChatBody } from "../types.js";

/** Redact PII in-place across all messages; store the encrypted token map on ctx. */
export function piiRedaction() {
  return (req: AppRequest, _res: Response, next: NextFunction): void => {
    const body = req.body as ChatBody;
    const fullMap: Record<string, string> = {};
    body.messages = body.messages.map((m) => {
      const { redacted, map } = redactPii(m.content);
      Object.assign(fullMap, map);
      return { ...m, content: redacted };
    });
    if (Object.keys(fullMap).length > 0) {
      req.ctx.piiMap = encryptJson(fullMap, loadEnv().PII_ENCRYPTION_KEY);
    }
    next();
  };
}
