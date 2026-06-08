import { describe, it, expect, beforeEach } from "vitest";
import { loadEnv, resetEnvCache } from "../src/config/env.js";

const VALID_ENV = {
  PORT: "3000",
  MONGODB_URI: "mongodb://localhost:27017/test",
  REDIS_URL: "redis://localhost:6379",
  API_KEY_PEPPER: "pepper-for-testing-1234",
  PII_ENCRYPTION_KEY: "a".repeat(64),
};

beforeEach(() => {
  resetEnvCache();
});

describe("env config", () => {
  it("valid env object passes loadEnv", () => {
    const env = loadEnv(VALID_ENV as NodeJS.ProcessEnv);
    expect(env.PORT).toBe(3000);
    expect(env.MONGODB_URI).toBe("mongodb://localhost:27017/test");
    expect(env.PII_ENCRYPTION_KEY).toBe("a".repeat(64));
  });

  it("missing required field throws with field name in message", () => {
    const { MONGODB_URI: _, ...withoutMongo } = VALID_ENV;
    expect(() => loadEnv(withoutMongo as NodeJS.ProcessEnv)).toThrow("MONGODB_URI");
  });

  it("malformed PII_ENCRYPTION_KEY (not 64 hex) throws", () => {
    const badEnv = { ...VALID_ENV, PII_ENCRYPTION_KEY: "not-hex-and-not-64-chars" };
    expect(() => loadEnv(badEnv as NodeJS.ProcessEnv)).toThrow("PII_ENCRYPTION_KEY");
  });
});
