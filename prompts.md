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

## Prompt — Spec review approval

> approve

**Decision:** Spec approved as written (committed on branch `feat/securellm-gateway`,
commit `ee84340`). Proceeding to the `writing-plans` skill to produce the step-by-step
implementation plan.

---

## Prompt — Continue to implementation plan

> continue

**Decisions made while writing the plan:**
- **Spec correction (verified):** the Israeli national ID `987654321` (corpus PII-D2)
  **fails** the official check-digit algorithm. Gating redaction on the check digit
  would miss a mandated corpus entry, so the redactor matches any bare 9-digit run
  (conservative over-redaction). Spec §5.4 updated to match. *(This is also the
  "What you rejected" example for the deliverable PROMPTS.md.)*
- **Stack pinned:** Express 4, MongoDB native driver 6 (no Mongoose — smaller), ioredis 5,
  zod, pino + pino-http, `@anthropic-ai/sdk`, `openai`, Vitest + supertest, `ioredis-mock`
  for rate-limit unit tests. ESM + TS strict + `noUncheckedIndexedAccess`.
- **Pipeline shape:** auth → rateLimit → validateBody → injectionGuard → piiRedaction as
  Express middleware; chat handler runs provider + output validation; a central error
  handler writes exactly one audit record per request (allowed/blocked/error).
- **Rate limiter:** Redis sliding window via sorted set; unique members use
  `crypto.randomUUID()` (no `Math.random()`), per Fireblocks crypto rules.
- Plan saved to `docs/superpowers/plans/2026-06-06-securellm-gateway.md` (18 tasks, TDD,
  full code per step). Self-review: all 3 endpoints, 7 controls, full corpus coverage,
  Docker/CI, no placeholders.

---

## Prompt — Execution mode

> 1

**Decision:** Subagent-driven execution — a fresh subagent implements each plan task,
with review between tasks. Invoking the `subagent-driven-development` skill.

---

## Implementation execution (subagent-driven, Claude Code / Opus 4.8)

Built in 5 reviewed phases on branch `feat/securellm-gateway`. Each phase: implementer
subagent → independent spec-compliance review → independent code-quality review →
fixes → re-verify. Docker is unavailable in this environment, so Docker/Compose/CI
files were authored but the live `docker compose up` + real-Anthropic call are
deferred to the user.

- **Phase A (T0–T5):** scaffold + pure security cores (crypto, injection, PII, output).
  Review caught: output-validator false positive on "confirmed…system prompt";
  exported `/g` regex hazard; injection false positives (bare `\bdan\b`, "developer
  mode", broad "no restrictions"); missing cipher key-length guard; singular
  "environment variable" gap. All fixed; 50 tests.
- **Phase B (T6–T10):** errors/types, Mongo/Redis, audit, auth (HMAC + constant-time +
  role guard), Redis sliding-window rate limit. Review caught: silent fail-open on
  Redis pipeline error (changed to fail-closed/throw); missing `keyId` index; double
  DB fetch on hot path (now carried on ctx); untested `requireRole`. Fixed; 60 tests.
- **Phase C (T11–T15):** middleware, provider router, routes, error handler, app
  factory, bootstrap, seed. Review caught: Anthropic silently dropping `system`
  messages (now forwarded as top-level `system`); possible double audit write on
  success path; scattered unsafe casts (consolidated). Routing verified to resolve
  `/v1/chat`, `/v1/audit`, `/healthz` (avoided the plan's double-prefix trap). Fixed.
- **Phase D (T16–T17):** Dockerfile (multi-stage, non-root, healthcheck added),
  docker-compose (gateway+mongo+redis, one command), CI (typecheck/test/gitleaks),
  integration tests. Strengthened to endpoint-level corpus coverage: all 12 INJ-* →
  400 + audit blocked/injection; all 3 PII-* redacted before the provider; output-echo
  → 502 + audit blocked/output_validation. Also fixed a flaky crypto tamper test. 79 tests.
- **Phase E (T18):** README (run/env/per-control/limitations) + this PROMPTS.md.

**Multi-tool decision:** to satisfy PROMPTS.md #2 honestly, a second AI tool (non-Claude)
performs an adversarial security review of `src/security/injection/rules.ts`; its
findings are triaged (accept/reject with reasons) and the exchange recorded here.

---
