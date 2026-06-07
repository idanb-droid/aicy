import type { Logger as PinoLogger, LoggerOptions } from "pino";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// pino is CJS with a callable default
const pinoFactory = require("pino") as (opts: LoggerOptions) => PinoLogger;

export const logger = pinoFactory({
  level: process.env.LOG_LEVEL ?? "info",
  redact: {
    paths: ["req.headers['x-api-key']", "req.headers.authorization", "*.apiKey", "*.keyHash", "*.pepper"],
    censor: "[REDACTED]",
  },
});

export type Logger = PinoLogger;
