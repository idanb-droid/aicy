# SecureLLM Gateway

A production-grade Express proxy that enforces a uniform security and audit layer on every LLM call routed through it, so application teams never re-implement authentication, rate limiting, injection detection, PII redaction, output validation, or audit logging.

---

## How to Run

### Docker Compose (recommended)

1. Copy the example env file and fill in the required values:

   ```bash
   cp .env.example .env
   ```

2. Set the three required secrets in `.env`:

   | Variable | How to generate |
   |---|---|
   | `ANTHROPIC_API_KEY` | Your Anthropic key (at least one provider key is required) |
   | `API_KEY_PEPPER` | Any random string of 32+ characters |
   | `PII_ENCRYPTION_KEY` | `openssl rand -hex 32` (produces the required 64 hex chars) |

3. Start the full stack (gateway + MongoDB + Redis) with a single command:

   ```bash
   docker compose up --build
   ```

   The gateway waits for healthy Mongo and Redis before accepting traffic.

4. Seed one client key and one admin key (run **once**; keys are printed to stdout and never shown again):

   ```bash
   docker compose exec gateway node dist/scripts/seed.js
   ```

   Output looks like:
   ```
   === Seeded API keys (store securely; shown ONCE) ===
   client keyId=key_client_ab12cd34  x-api-key: sllm_client_<48 hex chars>
   admin  keyId=key_admin_ef56gh78   x-api-key: sllm_admin_<48 hex chars>
   ====================================================
   ```

### Example curl calls

```bash
# Health check (no auth required)
curl http://localhost:3000/healthz

# Chat request
curl -X POST http://localhost:3000/v1/chat \
  -H "Content-Type: application/json" \
  -H "x-api-key: sllm_client_<your-key>" \
  -d '{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Summarise Q3 results."}],"max_tokens":256}'

# Audit log (admin key required)
curl "http://localhost:3000/v1/audit?since=0&limit=50" \
  -H "x-api-key: sllm_admin_<your-key>"
```

### Local development

```bash
npm install
npm test          # run Vitest (no live DB or Redis needed — integration tests stub both)
npm run dev       # tsx watch mode, hot-reload on src/ changes
```

---

## Environment Variables

| Variable | Required? | Purpose |
|---|---|---|
| `MONGODB_URI` | Yes | MongoDB connection string. Default in Compose: `mongodb://mongo:27017/securellm` |
| `REDIS_URL` | Yes | Redis connection string. Default in Compose: `redis://redis:6379` |
| `ANTHROPIC_API_KEY` | At least one provider key required | Enables `claude-3-5-sonnet` model. Without it `/v1/chat` returns 503 for that model. |
| `OPENAI_API_KEY` | No (optional) | Enables `gpt-4o` model. If absent, requests for `gpt-4o` return 503. |
| `API_KEY_PEPPER` | Yes | Random 32+ char secret used as the HMAC key when hashing API keys at rest. Must be kept stable or all existing keys become invalid. |
| `PII_ENCRYPTION_KEY` | Yes | Exactly 64 hex characters (32 bytes). Used for AES-256-GCM encryption of the PII token map stored in audit records. Generate: `openssl rand -hex 32` |
| `RATE_LIMIT_DEFAULT` | No | Per-key sliding-window limit in requests per minute. Defaults to `30`. |
| `PORT` | No | TCP port the gateway listens on. Defaults to `3000`. |
| `LOG_LEVEL` | No | Pino log level (`trace`, `debug`, `info`, `warn`, `error`). Defaults to `info`. |

All variables are validated by Zod at startup. The process fails fast with a descriptive error if any required variable is missing or malformed.

---

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | None | Returns Mongo reachability, Redis reachability, and per-provider readiness. HTTP 200 when all healthy; 503 with a per-dependency status object when any dependency is down or no provider key is configured. |
| `POST` | `/v1/chat` | `x-api-key` (client or admin role) | Routes a chat request through the full security pipeline (auth → rate limit → body validation → injection detection → PII redaction → provider call → output validation) and returns the model's response. |
| `GET` | `/v1/audit` | `x-api-key` (admin role only) | Returns audit log entries. Query params: `since` (ISO timestamp or epoch ms, default `0`) and `limit` (1–500, default 100). Returns `{ count, entries }` sorted newest-first. |

### `POST /v1/chat` request body

```json
{
  "model": "claude-3-5-sonnet | gpt-4o",
  "messages": [
    { "role": "user | assistant | system", "content": "string (non-empty)" }
  ],
  "max_tokens": 1024
}
```

`max_tokens` is optional and defaults to `1024` (maximum accepted: `4096`). The body is rejected with `400` if it does not conform to this schema.

---

## Security Architecture

### Authentication

Every request to `/v1/chat` and `/v1/audit` must carry an `x-api-key` header. The raw key is never stored. On receipt the gateway computes `HMAC-SHA256(rawKey, API_KEY_PEPPER)` and looks up that hash in MongoDB's indexed `apikeys` collection. If a record is found, a `crypto.timingSafeEqual` comparison on the hash bytes confirms the match as defense-in-depth against timing attacks. Each key document carries a `role` of either `client` or `admin`; `/v1/audit` enforces the `admin` role and returns `403` for any other role. A missing or non-matching key returns `401`. API keys follow the format `sllm_<role>_<48 hex chars>` and are seeded via `src/scripts/seed.ts`, which prints them exactly once. The pepper-based HMAC is the correct choice for high-entropy keys because it allows an indexed lookup — bcrypt/Argon2 (correct for low-entropy passwords) would require a full collection scan and prohibitive latency.

### Rate Limiting

Each authenticated key is subject to a Redis sliding-window rate limit keyed by `keyId`. On every request, a four-command pipeline atomically removes entries older than 60 seconds, records the current timestamp, reads the window count, and sets a TTL. The default limit is 30 requests per minute; individual keys can carry a `rateLimitPerMin` override. Requests over the limit receive `429`. If the Redis pipeline returns an error or null result, the middleware throws immediately rather than silently permitting the request — the limiter fails closed, trading a brief availability impact for the guarantee that the control is never silently bypassed.

### Prompt-Injection Detection

Every message `content` field is normalized before matching: Unicode NFKC normalization, zero-width and bidirectional-control character stripping, lowercasing, and whitespace collapsing. This defeats common evasion techniques such as mixed case, injected whitespace, and Unicode control characters. Normalized text is then matched against 20 named regex rules covering corpus categories A through E: category A (direct instruction override — "ignore previous instructions", unrestricted/debug/jailbreak mode, forged `<|im_start|>` delimiters, authority spoofing); category B (system-prompt extraction — "repeat your initial instructions", "print everything above", env-var/API-key dump requests); category C (persona and roleplay hijack — DAN-style jailbreaks, Python REPL impersonation, format-bypass JSON signals); and category E (indirect/smuggled injection — end-marker injection, HTML-comment smuggling, translate-and-execute smuggling). A match returns `400` with the `prompt_injection_detected` error code and the rule IDs and categories that fired. The audit record captures the same rule information so every blocked request is traceable to its specific attack pattern.

### PII Redaction

Inbound message content is scanned for three categories of PII before it is sent to the provider: email addresses (including `+tag` variants and multi-label TLDs such as `.co.il`), phone numbers (Israeli `+972-5x-...`, `05x-...`, and `0x-...` formats as well as international `+CC`-prefixed numbers with separators), and Israeli national IDs (any standalone run of exactly 9 digits). Patterns run in that order — email and phone before the bare 9-digit matcher — and the phone pattern requires separator characters so it does not consume bare ID digits. Each detected span is replaced in-place with a reversible token (`[EMAIL_1]`, `[PHONE_1]`, `[ISR_ID_1]`, and so on); repeated occurrences of the same value reuse the same token. The provider receives only the redacted content. The `token → original` map is encrypted with AES-256-GCM (a fresh random 12-byte IV per record) using `PII_ENCRYPTION_KEY`, and the ciphertext is stored on the audit record. Originals are recoverable only by an admin via the audit path who holds the encryption key; no plaintext PII is persisted.

### Output Validation

The LLM response is treated as untrusted. Before returning any content to the caller, the gateway scans it against five output rules: OpenAI- and Anthropic-style secret keys matching `sk-(ant-)?[A-Za-z0-9_-]{16,}`, AWS access key IDs matching `AKIA[0-9A-Z]{16}`, JWT-shaped tokens matching the `eyJ...` three-part Base64url pattern, and echoed injection markers (`DEBUG_OK`, `[DAN]:`, `TEST_ECHO_9X7`, `COMPROMISED:`, `{"bypass": true`, and a standalone `CONFIRMED` immediately followed by a reference to a system prompt within 60 characters). A match returns `502` with the `unsafe_output` error code; the flagged content is never sent to the caller. The audit record is written with `status: blocked` and `blockedStage: output_validation`.

### Audit Log

Every request — allowed, blocked, or errored — produces exactly one MongoDB document in the `audit` collection. The record contains: `correlationId` (UUID, also echoed in the `x-correlation-id` response header), `ts`, `keyId`, `role`, `model`, `provider`, `status` (`allowed | blocked | error`), `threats` (array of `{id, category}` for each injection rule that fired), `requestHash` (SHA-256 of the raw validated request body, captured before PII redaction), `responseHash` (SHA-256 of the response text for allowed requests), `latencyMs`, `blockedStage`, `piiMap` (AES-256-GCM ciphertext of the token map when PII was detected), and `error` (for unexpected failures). Raw message content is never stored — only hashes, preserving integrity evidence without retaining payload data. The `ts` field is indexed; `/v1/audit` queries with `ts >= since`, sorts newest-first, and clamps the result to a maximum of 500 entries.

### Secrets Handling

Provider keys and cryptographic secrets are supplied exclusively through environment variables and are never present in source code, committed files, or logs. Pino is configured to redact the `x-api-key` header, `authorization` header, `apiKey`, `keyHash`, and `pepper` fields from all log output. `.env.example` contains only placeholder values. `.gitleaks.toml` extends the default ruleset and is checked on every push and pull request by a GitHub Actions job running `gitleaks/gitleaks-action@v2`.

---

## What This Service Does NOT Protect Against

**Pattern-based injection detection is not a complete defense.** The detector catches all corpus entries and tested variations, but novel obfuscated attacks not covered by the 20 rules will pass. NFKC normalization folds compatibility characters but does not neutralize Cyrillic or Greek homoglyphs that are visually identical to Latin characters — for example, a Cyrillic "а" in "ignore" is treated as a different code point and may not match.

**PII detection is regex- and locale-bounded.** The three patterns (email, Israeli phone/ID, international phone) cover the targeted corpus well but will miss PII formats from locales not represented. The Israeli national ID pattern matches any standalone 9-digit sequence and deliberately does not validate the official check digit, because the mandated test corpus includes `987654321`, which fails the check. This means the gateway over-redacts bare 9-digit numbers that are not valid Israeli IDs. False positives are the safe bias in a regulated gateway.

**No semantic or LLM-based classifier runs in the hot path.** This is deliberate: deterministic regex rules are testable, have zero added latency, and cost nothing per request. A model-based classifier would provide better recall on novel attacks but would add latency, cost, and an additional point of failure.

**Rate limiting relies on shared Redis.** The sliding-window implementation is correct and works across multiple gateway instances sharing the same Redis. It has not been load-tested under high concurrency. If Redis becomes unreachable, the rate-limit middleware throws (fails closed), which will cause all `/v1/chat` requests to return `500` until Redis recovers. This trades a brief availability impact for the guarantee that the control is never silently skipped.

**Provider-side behavior is out of scope.** Once redacted input is dispatched to Anthropic or OpenAI, the gateway has no control over how those providers store, log, or process the request. The output validator blocks leaked secrets in the response, but provider-side data retention policy is outside this service's threat model.

**A compromised valid API key has limited defenses.** Beyond per-key rate limits, there is no anomaly detection, IP allowlisting, or short-lived token rotation. Key compromise should be handled by seeding a new key and revoking (deleting) the old one from MongoDB.

---

## Known Limitations

- **Horizontal scaling of the rate limiter** is supported via shared Redis and is architecturally correct, but it has not been load-tested. Single-instance behavior is well-covered by the test suite.
- **Logger initialization order:** `src/logger.ts` reads `process.env.LOG_LEVEL` at module import time, before the Zod env validation in `src/config/env.ts` runs. In practice this is harmless — the logger simply falls back to `"info"` if the variable is absent — but the value is not validated by the schema at the point of first use.
- **Floating image tags in CI:** `docker-compose.yml` references `mongo:7` and `redis:7-alpine`, and the CI workflow uses `gitleaks/gitleaks-action@v2` and `actions/checkout@v4` without digest pins. Pinning to digest hashes is recommended hardening for production deployments.
- **Only Anthropic is wired live by default.** The `claude-3-5-sonnet` model routes to Anthropic and works as soon as `ANTHROPIC_API_KEY` is set. The `gpt-4o` model routes to OpenAI and returns `503` unless `OPENAI_API_KEY` is also set.

---

## Testing

```bash
npm test
```

Runs the full Vitest suite (no live MongoDB or Redis required — the integration tests stub both). The suite is organized as follows:

- **`test/injection.test.ts`** — unit tests against the pure `detectInjection` function. All 12 corpus entries (INJ-A1 through INJ-E3) are verified to be detected. Four variation tests confirm that case differences, extra whitespace, zero-width character insertion, and mixed casing do not evade detection. Seven benign-input tests confirm that normal prose is not flagged.
- **`test/pii.test.ts`** — unit tests against `redactPii` and `restorePii`. All three corpus entries (PII-D1, PII-D2, PII-D3) are verified to have every PII span redacted, including the deliberately invalid check-digit ID `987654321`. Round-trip reversibility is asserted for each. Two false-positive tests confirm that ordinary numbers and prose are not redacted.
- **`test/output.test.ts`** — unit tests against `validateOutput`. All five rule types (sk- key, AWS key, JWT, injection echo markers, `CONFIRMED` + system prompt dump) are verified to be flagged. Clean responses and normal prose referencing system prompts are verified to pass.
- **`test/auth.test.ts`** — unit tests for HMAC hashing and constant-time comparison.
- **`test/crypto.test.ts`** — unit tests for AES-256-GCM encrypt/decrypt round-trips.
- **`test/rateLimit.test.ts`** — unit tests for the `slidingWindowAllow` function.
- **`test/integration.test.ts`** — end-to-end pipeline tests using `supertest` with stubbed provider, auth, rate limiter, and audit service. Covers: benign request → 200 + `status: allowed` audit; injection → 400 + `status: blocked` audit; PII in input → 200 + provider receives redacted content + `piiMap` present in audit; malicious provider output → 502 + `status: blocked` audit. Also exercises all 12 INJ corpus entries at the HTTP layer and all 3 PII cases at the HTTP layer.

---

## Architecture

The gateway follows a pure-core / thin-middleware pattern. Each security control is implemented as a side-effect-free function in `src/security/` and tested in isolation without Express or database dependencies. A thin Express middleware in `src/middleware/` wires the pure function into the request pipeline and handles error propagation. The pipeline order for `POST /v1/chat` is:

```
correlationId  →  auth  →  rateLimit  →  validateBody
  →  injectionDetect  →  piiRedact  →  providerCall  →  outputValidate  →  respond
```

Every terminal outcome (allowed, blocked, or unexpected error) writes exactly one audit record, keyed by `correlationId`.

Full design rationale, threat model, and the original challenge brief are in:

- `docs/superpowers/specs/2026-06-06-securellm-gateway-design.md` — approved design spec
- `docs/superpowers/plans/2026-06-06-securellm-gateway.md` — implementation plan
