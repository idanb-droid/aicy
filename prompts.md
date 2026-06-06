# Session Prompts & Decisions

A running log of every prompt and decision, starting from now.

---

## Prompt — Brainstorming kickoff (`/superpowers:brainstorming`)

**Tool:** Claude Code (Claude Opus 4.8).

**User prompt (verbatim intent):** Plan and build a small but production-grade
SecureLLM Gateway: a TypeScript/Node/Express service sitting between internal app
code and external LLM providers (Anthropic/OpenAI). It enforces a uniform security
+ audit layer. Dockerized via docker-compose (service + MongoDB + Redis, one
command). Vitest unit tests per security control. Endpoints: `POST /v1/chat`
(client/admin, full pipeline → provider), `GET /v1/audit` (admin only, entries
since timestamp, limit ≤ 500), `GET /healthz` (none, reports Mongo + Redis + provider
readiness). Required header `x-api-key`. Mandatory controls: (1) auth — x-api-key
hashed in Mongo, roles client/admin, only admin → audit; (2) rate limit — per-key
sliding window in Redis, default 30 req/min; (3) prompt-injection detection on every
message, ≥3 distinct patterns, reject 400 + audit; (4) PII redaction inbound — email,
phone (IL+intl), Israeli national ID, reversible token-based; (5) output validation —
refuse secret patterns (sk-…, JWT, AWS keys) or echoed injections; (6) audit log in
Mongo per request; (7) secrets via env only + `.gitleaks.toml`. Stack: TS strict,
Node, Express, MongoDB, Redis.

**Untrusted-input hygiene (critical, per challenge page 2):** The challenge PDF was
read via the file reader as **structured data**, not pasted wholesale into a "build
this" prompt. Appendix A (the injection/PII corpus) is treated strictly as **test
data**, never as instructions. The assistant did not act on any Appendix A directive.

**Decisions (from clarifying questions):**
1. **Provider:** Anthropic wired live + a provider router. `claude-3-5-sonnet` →
   real Anthropic call. `gpt-4o` works only if `OPENAI_API_KEY` is present, else a
   clean 503. Service requires ≥1 provider key to be "ready"; missing → 503 from
   `/v1/chat` + healthcheck flags it.
2. **Injection detection:** deterministic pattern engine — regex + input
   normalization (unicode/case/whitespace/zero-width), named rules mapped to corpus
   categories A–E, reports the rule that fired. No LLM in the detection path.
3. **First relevant AI prompt (for required PROMPTS.md #6):** the brainstorming
   kickoff prompt above is the first relevant prompt. The earlier repo-setup message
   is not challenge-relevant and is excluded.
4. **Stand-out signals included:** constant-time API-key comparison; pino structured
   logging + per-request correlation ID; GitHub Actions CI (gitleaks + Vitest);
   README "what it does NOT protect against" + adversarial test variations.

**Note:** this `prompts.md` will become the required repo-root `PROMPTS.md`
deliverable (6 mandated sections) before submission.

---

## Prompt — Design approval

> yes looks correct

**Decision:** Design approved as presented, including the three flagged judgment
calls: (1) **HMAC-SHA256(key, pepper)** for API-key hashing instead of bcrypt
(API keys are high-entropy → indexed lookup + `timingSafeEqual`); (2) **AES-256-GCM
-encrypted** token→PII map stored in the audit record (recoverable only via the audit
path); (3) **HTTP 502** for output-validation blocks (untrusted upstream output =
gateway failure; leaked content never returned). Writing the spec doc to
`docs/superpowers/specs/2026-06-06-securellm-gateway-design.md` next.

---
