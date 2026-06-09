// Silence structured logs during tests (logger reads LOG_LEVEL at import time).
process.env.LOG_LEVEL = "silent";
