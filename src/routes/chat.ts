import { Router } from "express";
import { getProvider } from "../providers/index.js";
import { validateOutput } from "../security/output/validator.js";
import { writeAudit } from "../audit/audit.service.js";
import { sha256 } from "../middleware/correlation.js";
import { OutputBlockedError } from "../errors.js";
import type { AppRequest, ChatBody } from "../types.js";

export const chatRouter = Router();

// Mounted behind: authenticate → rateLimit → validateChatBody → injectionGuard → piiRedaction.
chatRouter.post("/", async (req, res, next) => {
  const ctx = (req as AppRequest).ctx;
  try {
    const body = req.body as ChatBody;
    const provider = getProvider(body.model);
    ctx.provider = provider.name;

    const result = await provider.chat({ model: body.model, messages: body.messages, maxTokens: body.max_tokens });

    const verdict = validateOutput(result.content);
    if (!verdict.clean) throw OutputBlockedError({ findings: verdict.findings });

    await writeAudit({
      correlationId: ctx.correlationId,
      ts: new Date(),
      keyId: ctx.keyId,
      role: ctx.role,
      model: ctx.model,
      provider: ctx.provider,
      status: "allowed",
      threats: ctx.threats,
      requestHash: ctx.requestHash,
      responseHash: sha256(result.content),
      latencyMs: Date.now() - ctx.startTime,
      ...(ctx.piiMap ? { piiMap: ctx.piiMap } : {}),
    });

    res.json({ model: body.model, content: result.content });
  } catch (err) {
    next(err);
  }
});
