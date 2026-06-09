import { PII_PATTERNS, type PiiCategory } from "./patterns.js";

export type PiiMap = Record<string, string>; // token -> original

export interface RedactionResult { redacted: string; map: PiiMap; }

/** Replace each PII span with a reversible token. Patterns run in priority order. */
export function redactPii(input: string): RedactionResult {
  const map: PiiMap = {};
  const valueToToken = new Map<string, string>();
  const counters: Record<PiiCategory, number> = { EMAIL: 0, PHONE: 0, ISR_ID: 0 };
  let out = input;

  for (const { category, regex } of PII_PATTERNS) {
    // Build a fresh /g regex each call so callers using .test() on the exported patterns
    // never corrupt lastIndex on the shared regex object.
    const globalRegex = new RegExp(regex.source, regex.flags + "g");
    out = out.replace(globalRegex, (match) => {
      const existing = valueToToken.get(match);
      if (existing) return existing;
      counters[category] += 1;
      const token = `[${category}_${counters[category]}]`;
      valueToToken.set(match, token);
      map[token] = match;
      return token;
    });
  }
  return { redacted: out, map };
}

/** Inverse of redactPii — used on the audit path to recover originals. */
export function restorePii(redacted: string, map: PiiMap): string {
  let out = redacted;
  for (const [token, original] of Object.entries(map)) {
    out = out.split(token).join(original);
  }
  return out;
}
