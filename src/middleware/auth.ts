import type { Response, NextFunction } from "express";
import { hashApiKey, safeEqualHex } from "../security/crypto/keys.js";
import { apiKeyCollection, type ApiKeyRecord } from "../auth/apikey.model.js";
import { loadEnv } from "../config/env.js";
import { AuthError, ForbiddenError } from "../errors.js";
import type { AppRequest } from "../types.js";

type LookupFn = (keyHash: string) => Promise<ApiKeyRecord | null>;

const defaultLookup: LookupFn = (keyHash) => apiKeyCollection().findOne({ keyHash });

/** Pure-ish resolver: hash the raw key, look it up, constant-time confirm. */
export async function resolveApiKey(rawKey: string, pepper: string, lookup: LookupFn): Promise<ApiKeyRecord> {
  if (!rawKey) throw AuthError("Missing x-api-key header");
  const keyHash = hashApiKey(rawKey, pepper);
  const record = await lookup(keyHash);
  if (!record || !safeEqualHex(keyHash, record.keyHash)) throw AuthError();
  return record;
}

/** Express middleware: authenticate the request and attach identity to ctx. */
export function authenticate(lookup: LookupFn = defaultLookup) {
  return async (req: AppRequest, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawKey = (req.header("x-api-key") ?? "").trim();
      const record = await resolveApiKey(rawKey, loadEnv().API_KEY_PEPPER, lookup);
      req.ctx.keyId = record.keyId;
      req.ctx.role = record.role;
      if (record.rateLimitPerMin !== undefined) req.ctx.rateLimitPerMin = record.rateLimitPerMin;
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Role guard factory; use requireRole("admin") on /v1/audit. */
export function requireRole(role: "admin" | "client") {
  return (req: AppRequest, _res: Response, next: NextFunction): void => {
    if (req.ctx.role !== role && !(role === "client" && req.ctx.role === "admin")) {
      next(ForbiddenError());
      return;
    }
    next();
  };
}
