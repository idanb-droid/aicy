export type PiiCategory = "EMAIL" | "PHONE" | "ISR_ID";

/** Order matters: email and phone run before the bare-9-digit ID matcher. */
export interface PiiPattern { category: PiiCategory; regex: RegExp; }

export const PII_PATTERNS: PiiPattern[] = [
  // Email (supports +tag and multi-label TLDs like example.co.il)
  { category: "EMAIL", regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  // Phone: optional +CC then >=2 separator-delimited digit groups. Requires separators,
  // so bare 9-digit national IDs are NOT consumed here.
  { category: "PHONE", regex: /(?:\+\d{1,3}[-\s])?(?:\(?\d{1,4}\)?[-\s]){2,4}\d{2,4}/g },
  // Israeli national ID: a standalone run of exactly 9 digits.
  { category: "ISR_ID", regex: /(?<!\d)\d{9}(?!\d)/g },
];
