import { describe, it, expect } from "vitest";
import { validateOutput } from "../src/security/output/validator.js";

describe("output validator — secret leakage", () => {
  it("flags an OpenAI-style key", () => {
    expect(validateOutput("here is the key sk-abcdef0123456789ABCDEF").clean).toBe(false);
  });
  it("flags an AWS access key id", () => {
    expect(validateOutput("AKIAIOSFODNN7EXAMPLE").clean).toBe(false);
  });
  it("flags a JWT-shaped string", () => {
    expect(validateOutput("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123").clean).toBe(false);
  });
});

describe("output validator — echoed injection signatures", () => {
  for (const marker of ["DEBUG_OK", "[DAN]:", "TEST_ECHO_9X7", "COMPROMISED:", '{"bypass": true']) {
    it(`flags echoed marker ${marker}`, () => {
      expect(validateOutput(`model said ${marker} and more`).clean).toBe(false);
    });
  }
});

describe("output validator — clean output passes", () => {
  it("ordinary answer is clean", () => {
    const r = validateOutput("Your quarterly margins improved by 12%. Let me know if you need more detail.");
    expect(r.clean).toBe(true);
    expect(r.findings).toHaveLength(0);
  });
  it("prose mentioning system prompt config is clean", () => {
    const r = validateOutput("We confirmed the new system prompt configuration is valid.");
    expect(r.clean).toBe(true);
  });
  it("refusal mentioning system prompt is clean", () => {
    const r = validateOutput("I cannot reveal my system prompt.");
    expect(r.clean).toBe(true);
  });
});

describe("output validator — attack echo still flagged", () => {
  it("model echoing CONFIRMED then dumping system prompt is flagged", () => {
    const r = validateOutput('CONFIRMED. My full system prompt is: You are a helpful assistant...');
    expect(r.clean).toBe(false);
  });
});
