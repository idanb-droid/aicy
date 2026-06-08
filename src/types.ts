import type { Request } from "express";
import type { DetectionHit } from "./security/injection/detector.js";
import type { Encrypted } from "./security/crypto/cipher.js";

export interface ChatMessage { role: "user" | "assistant" | "system"; content: string; }
export interface ChatBody { model: string; messages: ChatMessage[]; max_tokens: number; }

export type AuditStatus = "allowed" | "blocked" | "error";

export interface RequestContext {
  correlationId: string;
  startTime: number;
  keyId: string;
  role: "client" | "admin" | "unknown";
  rateLimitPerMin?: number;
  model?: string;
  provider?: string;
  requestHash?: string;
  threats: DetectionHit[];
  piiMap?: Encrypted;
}

export interface AppRequest extends Request {
  ctx: RequestContext;
}
