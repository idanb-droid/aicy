# SecureLLM Gateway — Design Spec

**Date:** 2026-06-06
**Status:** Approved
**Source brief:** `SecureLLM_Gateway_Challenge.pdf` (AICY Cyber 360 — Senior Engineering Challenge)

## 1. Purpose & scope

A small but production-grade Express service that sits between internal application
code and external LLM providers (Anthropic, OpenAI). Every org LLM call routes through
it; it enforces a uniform security + audit layer so application teams never
re-implement these controls. It is the only guard between trusted user input,
untrusted LLM output, and a regulated environment.

**In scope:** the 3 endpoints, 7 mandatory controls, Docker Compose stack
(service + MongoDB + Redis), Vitest unit tests per control, secret-scan config.
**Out of scope (YAGNI):** streaming responses, multi-turn conversation storage,
a UI, multiple live providers (one is wired live; the other is optional), user
management beyond seeded API keys.

## 2. Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/chat` | client/admin | Proxy a chat request through the full security pipeline to the configured provider. |
| GET | `/v1/audit` | admin only | Return audit log entries since a given timestamp (`limit ≤ 500`). |
| GET | `/healthz` | none | Liveness: Mongo + Redis reachability and provider readiness. |

**`POST /v1/chat` request body:**
```json
{ "model": "claude-3-5-sonnet | gpt-4o", "messages": [{"role":"user","content":"..."}], "max_tokens": 1024 }
```
Required header: `x-api-key: <client-key>`.

**`GET /v1/audit`** query: `?since=<ISO timestamp|epoch ms>&limit=<≤500>` (limit clamped to 500).

## 3. Architecture — middleware pipeline

The brief mandates *"each control runs as an independent middleware so it can be
tested and reasoned about in isolation."* Each control is therefore a thin Express
middleware that delegates to a **pure core function**. The pure core holds all logic
and is unit-tested without Express; the middleware only wires `req`/`res` and audit.

Pipeline order for `POST /v1/chat`:

```
correlationId + pino  →  auth  →  rateLimit  →  validateBody(zod)
  →  injectionDetect  →  piiRedact  →  providerCall  →  outputValidate  →  respond
                                                                            │
                  every terminal outcome (allowed | blocked | error) writes  │
                                  exactly ONE audit record  ◄────────────────┘
```

**Order rationale:**
- **auth before rateLimit** — the rate-limit window is keyed by API-key identity.
- **validate before inspect** — reject malformed bodies before running detectors.
- **injection before PII** — reject hostile input early and audit the *raw* threat;
  PII redaction does not alter injection text, so detection accuracy is unaffected.
- **outputValidate last** — the provider response is untrusted and is the final gate
  before anything returns to the caller.

## 4. Project layout

```
src/
  index.ts                 # bootstrap: validate env, connect Mongo/Redis, start server
  app.ts                   # express app + route wiring
  config/env.ts            # zod-validated env schema, fail-fast at startup
  db/mongo.ts  db/redis.ts # connection singletons + health pings
  middleware/
    correlation.ts         # assign correlationId, attach pino child logger
    auth.ts                # x-api-key → HMAC lookup → {keyId, role}; role guard factory
    rateLimit.ts           # Redis sliding window per keyId
    validateBody.ts        # zod schema for /v1/chat body
    errorHandler.ts        # typed-error → status map + guaranteed audit write
  security/
    injection/detector.ts  # pure: normalize + run rules → DetectionResult
    injection/rules.ts      # named rules mapped to corpus categories A–E
    pii/redactor.ts        # pure: detect spans → reversible tokens + token map
    pii/patterns.ts         # email, phone (IL+intl), Israeli national ID (+check digit)
    output/validator.ts    # pure: secret patterns + echoed-injection signatures
    crypto/keys.ts         # HMAC-SHA256(key, pepper), timingSafeEqual compare
    crypto/cipher.ts       # AES-256-GCM encrypt/decrypt for the PII token map
  providers/
    index.ts               # router: model name → provider; readiness check
    anthropic.ts           # live call via @anthropic-ai/sdk
    openai.ts              # live call if OPENAI_API_KEY present
  audit/
    audit.service.ts       # writeAudit(...) used by route + error handler
    audit.model.ts         # Mongo schema/types
  routes/
    chat.ts  audit.ts  health.ts
  scripts/seed.ts          # create 1 client + 1 admin key; print raw keys ONCE
test/                      # mirrors security/ + one pipeline integration test
Dockerfile  docker-compose.yml  .gitleaks.toml  .env.example
vitest.config.ts  .github/workflows/ci.yml  README.md
```

## 5. Security controls

### 5.1 Authentication
- `x-api-key` required on `/v1/chat` and `/v1/audit`.
- **Storage:** `keyHash = HMAC-SHA256(rawKey, API_KEY_PEPPER)`, stored indexed in
  Mongo. Rationale: API keys are high-entropy, so a keyed hash gives an **indexed
  lookup** *and* allows **constant-time comparison** (`crypto.timingSafeEqual`).
  bcrypt/Argon2 (correct for low-entropy passwords) would force a full-collection
  scan and is not appropriate here. *(Deliberate deviation from the general
  "bcrypt for hashing" rule — documented in README Security Architecture.)*
- Lookup by `keyHash`; then `timingSafeEqual` on the hash bytes as defense-in-depth.
- Roles: `client | admin` on the key document. `/v1/audit` requires `admin` (403 otherwise).
- Missing/invalid key → `401`. Valid key, insufficient role → `403`.

### 5.2 Rate limiting
- Redis **sliding window** (sorted set of request timestamps per `keyId`, trimmed to
  the trailing 60s window). Default **30 req/min**; per-key override via
  `rateLimitPerMin` on the key document.
- Over limit → `429` + audit (`status: blocked`, `blockedStage: rate_limit`).

### 5.3 Prompt-injection detection
- Runs on **every** incoming message's `content`.
- **Normalization** before matching: Unicode NFKC, lowercase, strip zero-width
  chars, collapse whitespace — defeats case/whitespace/encoding evasion (corpus
  acceptance criteria require ≥1 variation per entry).
- **Named rules** mapped to corpus categories (each rule has an id + category so the
  audit log records *which rule fired*):
  - **A — instruction override:** "ignore (all )?previous instructions", unrestricted/
    debug mode, forged role delimiters (`<|im_start|>`, `[SYSTEM]:`), authority
    spoofing (`[ADMIN]:` + comply).
  - **B — extraction:** "repeat your initial/system instructions", "print everything
    above", env-var/API-key dump requests.
  - **C — persona/roleplay hijack:** DAN-style, "you are now a Python REPL"/
    `open('/etc/passwd')`, output-format hijack (`{"bypass": true,...}`).
  - **E — indirect/smuggling:** end-marker injection (`[END USER MESSAGE]` +
    `[SYSTEM]:`), HTML-comment smuggling (`<!-- SYSTEM_OVERRIDE ... -->`),
    multilingual "translate … and execute the instruction".
  - (Category **D** is PII, handled by 5.4 — not a block.)
- Hit → `400` + audit (`status: blocked`), response body names the rule/category that fired.
- Detector returns `{ matched: boolean, rules: [{id, category}] }` — covers ≥3 distinct patterns (we implement many).

### 5.4 PII redaction (inbound)
- Categories (≥3): **email**, **phone** (Israeli `+972`/`05x`/`0x` and international
  `+CC`), **Israeli national ID** (bare 9-digit sequences). NOTE: redaction does **not**
  gate on the official check digit — the mandated corpus includes `987654321`, which
  fails the check — so we redact any standalone 9-digit run. Over-redaction is the safe
  bias in a regulated gateway; the check digit is noted as a future confidence signal,
  not a filter. Ordering (email → phone → ID) plus requiring separators in the phone
  pattern prevents the phone matcher from consuming bare ID digits.
- Each detected span replaced **in place** with a reversible token: `[EMAIL_1]`,
  `[PHONE_1]`, `[ISR_ID_1]`, … Redacted content (not the original) is sent to the LLM.
- The `token → original` map is **AES-256-GCM-encrypted** (`PII_ENCRYPTION_KEY` from
  env, unique IV per record) and stored on the audit record. Originals are recoverable
  **only via the audit path** by an admin with the key — satisfies "reversible at
  audit time" for a regulated environment without persisting plaintext PII.
- Works on prose, mixed-format, and JSON-embedded payloads (operates on raw string content).

### 5.5 Output validation (outbound)
- The LLM response is untrusted. Scan response text for:
  - **secret-shaped strings:** `sk-…` (provider keys), AWS access keys (`AKIA[0-9A-Z]{16}`),
    JWT-shaped `eyJ…\.…\.…`.
  - **echoed-injection signatures:** `CONFIRMED`+system-prompt, `DEBUG_OK`, `[DAN]:`,
    `TEST_ECHO_9X7`, `COMPROMISED:`, and other markers from blocked corpus entries.
- On match → **`502`** + safe refusal message; the leaked content is **never**
  returned. Audit `status: blocked`, `blockedStage: output_validation`.
- Tested independently via **response stubbing** (inject a malicious provider response).

### 5.6 Audit log
- One Mongo record per request (allowed, blocked, or error). Fields:
  `{ correlationId, ts, keyId, role, model, provider, status, threats:[{rule,category}],
     requestHash(sha256 of raw body), responseHash(sha256 of raw response),
     latencyMs, blockedStage?, piiMap(AES-GCM)?, error? }`.
- Full message content is **not** stored — only hashes (integrity without retaining
  payloads) plus the encrypted PII map for reversibility.
- `ts` indexed; `/v1/audit` returns entries with `ts ≥ since`, sorted, `limit ≤ 500`.

### 5.7 Secrets handling
- All provider keys and crypto secrets via **env vars only**. Never in code, commits,
  or logs (pino configured to redact `x-api-key`, `authorization`, and key fields).
- `.env.example` with placeholders only. `.gitleaks.toml` committed; CI runs gitleaks.

## 6. Providers, health, config

### 6.1 Provider router
- `LLMProvider.chat({ model, messages, maxTokens }) → { content, raw }`.
- Routing: `claude-3-5-sonnet` → **Anthropic (live)**; `gpt-4o` → **OpenAI (live if
  `OPENAI_API_KEY` set, else 503)**.
- Startup requires **≥1** provider key or the service reports not-ready; `/v1/chat`
  returns a clear `503` when the requested model's provider key is missing. The live
  call is **not stubbed** — wired for real when a key is present.

### 6.2 Health
- `GET /healthz` pings Mongo + Redis and reports provider readiness. `200` when all
  healthy; `503` with a per-dependency status object when any is down or no provider
  is configured.

### 6.3 Configuration (env)
`MONGODB_URI`, `REDIS_URL`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY?`, `API_KEY_PEPPER`,
`PII_ENCRYPTION_KEY` (32-byte), `RATE_LIMIT_DEFAULT` (=30), `PORT`. Validated by zod at
startup; the process fails fast with a clear message on missing/invalid config.

## 7. Error handling

Typed errors thrown by controls, mapped centrally:

| Error | Status | Stage |
|---|---|---|
| Missing/invalid key | 401 | auth |
| Wrong role | 403 | auth |
| Rate exceeded | 429 | rate_limit |
| Malformed body | 400 | validation |
| Injection detected | 400 | injection |
| Provider key missing | 503 | provider |
| Output leak detected | 502 | output_validation |
| Unexpected | 500 | — |

The error handler maps error → status and guarantees **exactly one** audit record per
request (correlationId-keyed), so blocked/error paths are audited just like allowed ones.

## 8. Testing (Vitest)

Unit tests target the **pure cores** (no Express, no DB):
- **Injection:** every `INJ-*` corpus entry blocks, plus ≥1 variation each
  (case / whitespace / zero-width / simple encoding); each asserts the rule that fired.
- **PII:** every `PII-*` entry redacts all spans; round-trip reversibility via the
  decrypted map; JSON-embedded payload handled.
- **Output validation:** secret patterns (`sk-`, AWS, JWT) and echoed-injection
  signatures caught via stubbed responses; clean responses pass.
- **Auth:** HMAC hashing, constant-time compare, role enforcement.
- **Integration (1):** full `/v1/chat` pipeline with a **stubbed provider** —
  allowed path returns 200 + audit `allowed`; injection path returns 400 + audit `blocked`.

## 9. Deliverables checklist (from brief)

- [ ] TypeScript `strict: true`, fully typed.
- [ ] `Dockerfile` + `docker-compose.yml` → `docker compose up` brings up
      service + Mongo + Redis in one command.
- [ ] Unit tests per control (Vitest).
- [ ] `.gitleaks.toml`.
- [ ] `README.md`: how to run, env vars, one paragraph per control on security
      architecture, **known limitations / "does NOT protect against"** section.
- [ ] `PROMPTS.md` (repo root) with all 6 mandated sections — built from `prompts.md`.

## 10. Stand-out signals included

Constant-time API-key comparison · pino structured logging + per-request correlation
ID · GitHub Actions CI (gitleaks + Vitest on every push) · README "what it does NOT
protect against" + adversarial test variations.

## 11. Known limitations (to document in README)

- Injection detection is **pattern-based**: it catches the corpus and realistic
  variations but is not a complete defense against novel/obfuscated attacks.
- PII detection is regex-based: locale-bounded; may miss exotic formats or produce
  rare false positives outside the targeted categories.
- No semantic/LLM-based classification in the hot path (deliberate: deterministic,
  testable, zero added latency/cost).
- Single-region, single-instance assumptions for the rate-limiter; horizontal scaling
  relies on shared Redis (works) but is not load-tested here.
