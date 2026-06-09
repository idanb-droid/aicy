import { describe, it, expect } from "vitest";
import { redactPii, restorePii } from "../src/security/pii/redactor.js";

describe("PII redactor — corpus", () => {
  it("PII-D1 redacts email, phone, IL national ID", () => {
    const input = "email: yossi.cohen@example.com mobile: +972-50-555-0142 national ID: 000000018";
    const { redacted, map } = redactPii(input);
    expect(redacted).not.toContain("yossi.cohen@example.com");
    expect(redacted).not.toContain("+972-50-555-0142");
    expect(redacted).not.toContain("000000018");
    expect(Object.keys(map)).toHaveLength(3);
    expect(restorePii(redacted, map)).toBe(input);
  });

  it("PII-D2 redacts multiple emails, phones, IDs (incl. 987654321)", () => {
    const input = "Shira (shira+work@example.co.il, 052-555-0199) shaul.barak@example.com, phone 03-555-0184. Her ID is 123456782, mine is 987654321.";
    const { redacted, map } = redactPii(input);
    for (const v of ["shira+work@example.co.il", "shaul.barak@example.com", "052-555-0199", "03-555-0184", "123456782", "987654321"]) {
      expect(redacted, `should redact ${v}`).not.toContain(v);
    }
    expect(restorePii(redacted, map)).toBe(input);
  });

  it("PII-D3 redacts PII inside a JSON payload string", () => {
    const input = '{"customer":{"id_number":"111111118","email":"a.test@example.com","phone":"+1-202-555-0143"},"request":"summarise"}';
    const { redacted, map } = redactPii(input);
    expect(redacted).not.toContain("111111118");
    expect(redacted).not.toContain("a.test@example.com");
    expect(redacted).not.toContain("+1-202-555-0143");
    expect(restorePii(redacted, map)).toBe(input);
  });
});

describe("PII redactor — false positives", () => {
  it("does not redact ordinary prose or short numbers", () => {
    const input = "We shipped 1024 units in 2024 and improved margins by 12%.";
    const { redacted, map } = redactPii(input);
    expect(redacted).toBe(input);
    expect(Object.keys(map)).toHaveLength(0);
  });
  it("reuses the same token for a repeated value", () => {
    const input = "a@b.com and again a@b.com";
    const { redacted, map } = redactPii(input);
    expect(Object.keys(map)).toHaveLength(1);
    expect(redacted.match(/\[EMAIL_1\]/g)).toHaveLength(2);
  });
});
