# PROMPTS.md — How AI was used on this challenge

> Required by the brief, Section 4. The six numbered sections below answer the
> six required points in order. An appendix preserves the full chronological
> prompt/decision log.

## Untrusted-input hygiene (the behaviour under test, page 2)

The challenge PDF was treated as **untrusted input**. It was never dragged
wholesale into an AI panel with "help me build this". Instead it was read with a
file reader as **structured data**, and Appendix A (the injection / PII corpus)
was handled strictly as **test data** — copied into test fixtures and unit tests,
never pasted into a prompt as instructions. No Appendix A directive was ever
executed by an AI tool. The same discipline was applied when sending code to a
second vendor for review (see §2): only first-party regex source was shared — no
corpus, no secrets.

---

## 1. Tools used

| Tool | Used for |
|------|----------|
| **Claude Code (Claude Opus 4.8)** | Primary tool. Brainstorming → design spec → implementation plan → implementation. Implementation ran as a **subagent-orchestrated pipeline**: a fresh implementer agent per phase, then two *independent* reviewer agents per phase (one spec-compliance, one code-quality), then a fix agent — each a separate context so review wasn't biased by the implementer's own reasoning. Also: an independent adversarial red-team agent against the injection layer, debugging, all Vitest tests, Dockerfile / docker-compose / GitHub Actions CI, and the README. |
| **Gemini (web)** | Independent **second-vendor security review** of `src/security/injection/rules.ts` — to challenge and harden a control written by Claude (see §2). |

---

## 2. Why multiple tools — the cross-vendor moment

`src/security/injection/rules.ts` (the prompt-injection rule set) was **written by
Claude Code and then reviewed by Gemini** — two tools on the same solution file.

I gave Gemini only the normalizer + the regex rules (no challenge corpus, nothing
sensitive) and asked it, as a defensive reviewer, to find (a) coverage gaps and
(b) false positives a real coding-gateway would hit. I did **not** apply its
output blindly — I triaged every finding against the hard constraint that the
detector must still catch every Appendix A entry:

- **Accepted (5):** Gemini caught two real false positives my own review had
  missed — `B-secret-exfil` flagging *"print environment variables as json"*, and
  `B-reveal-prompt` flagging *"show me the original message format"*. I also took
  its `A-override` "context" false positive, a translate-the-system-prompt
  coverage gap, and a realistic `cat /etc/passwd` filesystem-probe variation.
- **Corrected (3):** several of Gemini's *fixes* were wrong and would have broken
  corpus coverage — its `B-secret-exfil` rewrite required the literal word "your"
  and would have stopped matching INJ-B3 ("**any** environment variables"); its
  `A-override` narrowing to "system instructions" would have stopped matching
  INJ-A1 ("ignore all previous **instructions**"); its `B-reveal-prompt` fix still
  matched its own example string. I re-derived anchors that fix the FP *and* keep
  the corpus caught, and added regression tests proving both.
- **Rejected (with reasons):** "developer mode" (re-introduces a false positive we
  had deliberately removed — a coding gateway sees "enable developer mode in VS
  Code" constantly; not in the corpus); Markdown/ChatML `^…$/m` anchors
  (incompatible with our whitespace-collapsing normalizer); and a **claimed batch
  of regex syntax errors** that did not exist — Gemini was reasoning over a
  Markdown-mangled paste where backslashes had been stripped; the real code
  compiles and the suite is green.

This is the point of using a second tool: a model with no memory of how I built
the detector found genuine blind spots, *and* confidently proposed fixes that
would have regressed the spec. Cross-checking — not trusting — is the value.

(Both review exchanges are committed: `923747c` first-pass red-team, `2579194`
Gemini triage.)

---

## 3. Three example prompts (verbatim)

### (a) Code generation — Claude Code (subagent implementer, Phase A)
> You are implementing Phase A (Tasks 0–5) of the SecureLLM Gateway implementation
> plan. […] The plan file is `docs/superpowers/plans/2026-06-06-securellm-gateway.md`.
> Read it and implement **Task 0, Task 1, Task 2, Task 3, Task 4, and Task 5**
> EXACTLY as written — they contain the complete code for every file and the exact
> commands to run. Use the code verbatim (it has been carefully designed). […]

*What I did with the output:* accepted it only after an independent spec-compliance
agent and a code-quality agent verified it by reading the code and running the
suite. That review caught real bugs (an output-validator false positive, a
`/g`-regex statefulness hazard), which were fixed before the phase was committed.

### (b) Security review — Gemini (web)
> I'm building a defensive security control for a TypeScript "SecureLLM Gateway"
> and I need a code review to improve its quality. Below is a deterministic,
> regex-based filter […]. Please act as a defensive code reviewer and assess the
> QUALITY and ROBUSTNESS of these regexes. I care about two failure modes:
> 1. COVERAGE GAPS (false negatives) […] 2. FALSE POSITIVES: benign strings that a
> legitimate developer using a coding assistant would plausibly send, but that
> wrongly match a rule […]. Rank findings by real-world severity. Be concrete
> (exact strings + exact regex fixes).

*What I did with the output:* triaged it as described in §2 — accepted 5 findings,
corrected 3 of its fixes that would have broken Appendix A coverage, rejected the
rest (including a hallucinated set of syntax errors). All accepted fixes shipped
with regression tests. *(First framing of this prompt was refused by Gemini as
"generate bypasses"; I reframed it as defensive code review — same review, no
offensive framing — and it proceeded.)*

### (c) Debugging / hardening — Claude Code (fix agent, Phase B)
> Code review of Phase B […] found issues to fix. […] **Fix 1 — rate limiter must
> not silently fail-open on a broken pipeline.** In `src/middleware/rateLimit.ts`,
> `slidingWindowAllow` currently defaults `count` to 0 when the Redis pipeline
> result is null/malformed, which silently allows every request if Redis errors.
> Change it so that if `res` is null, or the ZCARD result slot carries a command
> error, or the count value is missing, it THROWS […]. Do NOT add a fake
> fail-open; throwing is the desired behavior. […] Add a test […].

*What I did with the output:* applied the fix-closed behavior and kept the test
that asserts a Redis failure now rejects the request instead of waving it through.

---

## 4. What I rejected

**(a) Gating Israeli-ID redaction on the check digit.** The obvious "correct"
implementation validates the national-ID check digit before redacting. I rejected
it: corpus entry PII-D2 contains `987654321`, which **fails** the official
check-digit algorithm. A check-digit gate would have left a mandated PII value
un-redacted and leaked it to the provider. The redactor instead matches any bare
9-digit run (conservative over-redaction) — correct for the security goal even
though it is "wrong" by the formal ID spec.

**(b) Gemini's corpus-breaking regex fixes.** As detailed in §2, I rejected/rewrote
three of Gemini's proposed fixes because, while they fixed a false positive, they
would have stopped the detector from catching mandatory Appendix A entries
(INJ-A1, INJ-B3). I also rejected its claim that the rules contained regex syntax
errors — verified false against a clean compile and a green test suite.

---

## 5. What I would do with more time

1. **A semantic second layer behind the regex.** The deterministic rules are a
   cheap first filter and, by design, cannot catch paraphrase/synonym attacks
   ("override the earlier directives", novel persona names, base64-smuggled
   payloads). I would add a small, fast embedding classifier scoring each message
   for similarity to known-attack families and route only ambiguous cases to it —
   so the regex drops obvious noise and the classifier catches semantic variants
   without inflating false positives. *AI would help* draft the classifier
   service, generate a labelled training/eval set from the corpus families, and
   write the threshold-tuning harness.

2. **Live load + provider-parity testing.** The Anthropic path is wired for real,
   but I deferred the live `docker compose up` + real-key call and never load-
   tested the Redis sliding-window limiter under concurrency, nor brought the
   OpenAI path to full parity with the Anthropic one. I would add a k6/autocannon
   load test asserting the limiter holds under burst, and contract tests covering
   both providers. *AI would help* generate the load-test scripts and the provider
   contract fixtures, and diff the two providers' response handling for drift.

---

## 6. My first AI interaction on this challenge (verbatim)

**Tool: Claude Code (Claude Opus 4.8).**

The literal first prompt I sent to any AI tool on this challenge contained **no
challenge content at all** — it was repository setup:

> i created new repor for this project https://github.com/idanb-droid/aicy.git let
> set it up before we start working

The first time challenge material entered an AI tool was the next substantive
prompt, which invoked the brainstorming workflow with the requirements I had
**already vetted and summarised from the PDF** — deliberately not a wholesale paste
of the document. Its intent, verbatim in substance:

> Plan and build a small but production-grade SecureLLM Gateway: a
> TypeScript/Node/Express service between internal app code and external LLM
> providers (Anthropic/OpenAI), enforcing a uniform security + audit layer.
> Endpoints `POST /v1/chat`, `GET /v1/audit` (admin), `GET /healthz`. Mandatory
> controls: auth (hashed x-api-key, client/admin roles), per-key sliding-window
> rate limit, prompt-injection detection (≥3 patterns, reject 400 + audit),
> reversible token-based PII redaction (email / IL+intl phone / Israeli national
> ID), output validation (refuse sk-…/JWT/AWS secrets or echoed injections), Mongo
> audit log per request, secrets via env + `.gitleaks.toml`. Dockerised
> (service + Mongo + Redis, one command). Vitest per control. TS strict.

This ordering is the behaviour the brief tests for: the untrusted artifact was
read and vetted as data *before* any AI consumed its content.

---

# Appendix — chronological prompt & decision log

A running log of every prompt and decision, in order.

## Prompt — Brainstorming kickoff (`/superpowers:brainstorming`)
**Tool:** Claude Code (Opus 4.8). Plan/build the SecureLLM Gateway (full spec in §6).
The PDF was read as structured data; Appendix A treated as test data only.

**Decisions (from clarifying questions):**
1. **Provider:** Anthropic wired live + a provider router; `gpt-4o` works only if
   `OPENAI_API_KEY` is present, else a clean 503; service needs ≥1 provider key.
2. **Injection detection:** deterministic pattern engine (regex + normalization),
   no LLM in the detection path.
3. **First relevant AI prompt** for PROMPTS.md #6: the brainstorming kickoff (repo
   setup excluded as non-challenge content — but recorded verbatim in §6 for
   honesty).
4. **Stand-out signals:** constant-time key compare; pino + correlation ID; GitHub
   Actions CI; README "does NOT protect against".

## Prompt — Design approval → `yes looks correct`
Approved the three flagged judgment calls: **HMAC-SHA256(key, pepper)** for API-key
hashing instead of bcrypt (high-entropy keys → indexed lookup + `timingSafeEqual`);
**AES-256-GCM**-encrypted token→PII map in the audit record; **HTTP 502** for
output-validation blocks. Spec written to `docs/superpowers/specs/`.

## Prompt — Spec review → `approve`
Spec approved and committed. Proceeded to `writing-plans`.

## Prompt — Plan → `continue`
**Decisions:** the Israeli-ID check-digit rejection (see §4a); stack pinned (Express
4, Mongo driver 6, ioredis 5, zod, pino, Vitest); pipeline shape (auth → rateLimit →
validateBody → injectionGuard → piiRedaction → handler; one audit write per request
via the error handler); rate limiter uses `crypto.randomUUID()` (no `Math.random`).
18-task TDD plan saved.

## Prompt — Execution mode → `1`
Subagent-driven execution: implementer per task + independent review between tasks.

## Implementation execution (subagent-driven, Claude Code / Opus 4.8)
Five reviewed phases on `feat/securellm-gateway`. Each phase: implementer →
independent spec-compliance review → independent code-quality review → fixes →
re-verify. Docker authored but the live `docker compose up` + real-Anthropic call
deferred to the user (no Docker in the build environment).

- **Phase A (T0–T5):** scaffold + pure cores (crypto, injection, PII, output).
  Review caught an output-validator false positive, a `/g` regex hazard, injection
  false positives, a missing cipher key-length guard. Fixed; 50 tests.
- **Phase B (T6–T10):** errors/types, Mongo/Redis, audit, auth (HMAC +
  constant-time + role guard), Redis sliding-window limiter. Review caught a
  silent Redis fail-open (→ fail-closed/throw), a missing index, a double DB fetch,
  an untested role guard. Fixed; 60 tests.
- **Phase C (T11–T15):** middleware, provider router, routes, error handler, app
  factory, seed. Review caught Anthropic dropping `system` messages (→ forwarded),
  a possible double audit write, scattered unsafe casts (consolidated). Routing
  verified.
- **Phase D (T16–T17):** Dockerfile (multi-stage, non-root, healthcheck),
  docker-compose (one command), CI (typecheck/test/gitleaks), endpoint-level corpus
  integration tests. 79 tests.
- **Phase E (T18):** README + this PROMPTS.md.

## Decision — multi-tool review (PROMPTS.md #2)
First attempted a cross-vendor paste; reframed after a safety refusal (offensive →
defensive framing). Ran an independent Claude red-team agent (commit `923747c`,
+11 tests) and then a **Gemini (web)** review of the same `rules.ts` (commit
`2579194`). Triaged both: accepted real findings with regression tests, corrected
fixes that would have broken Appendix A coverage, rejected speculative/false ones
(full reasoning in §2). 98 tests passing; typecheck clean.
