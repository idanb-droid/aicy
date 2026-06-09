import { INJECTION_RULES, type Category } from "./rules.js";

export interface DetectionHit { id: string; category: Category; description: string; }
export interface DetectionResult { matched: boolean; rules: DetectionHit[]; }

/** Normalise text to defeat case/whitespace/zero-width/unicode evasion. */
export function normalize(input: string): string {
  return input
    .normalize("NFKC")
    .replace(/[​-‏‪-‮⁠﻿]/g, "") // zero-width / bidi
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

/** Run all rules against a single message's content. */
export function detectInjection(content: string): DetectionResult {
  const norm = normalize(content);
  const hits: DetectionHit[] = [];
  for (const rule of INJECTION_RULES) {
    if (rule.pattern.test(norm)) {
      hits.push({ id: rule.id, category: rule.category, description: rule.description });
    }
  }
  return { matched: hits.length > 0, rules: hits };
}

/** Detect across an array of messages; returns the union of hits. */
export function detectInjectionInMessages(messages: { content: string }[]): DetectionResult {
  const all: DetectionHit[] = [];
  for (const m of messages) all.push(...detectInjection(m.content).rules);
  // Also scan the joined turn: a trigger phrase split across messages (e.g.
  // "ignore all previous" + "instructions...") evades every per-message rule.
  if (messages.length > 1) {
    all.push(...detectInjection(messages.map((m) => m.content).join(" ")).rules);
  }
  const seen = new Set<string>();
  const deduped = all.filter((h) => (seen.has(h.id) ? false : (seen.add(h.id), true)));
  return { matched: deduped.length > 0, rules: deduped };
}
