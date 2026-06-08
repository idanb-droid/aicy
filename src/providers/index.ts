import { loadEnv } from "../config/env.js";
import { ProviderUnavailableError } from "../errors.js";
import { AnthropicProvider } from "./anthropic.js";
import { OpenAIProvider } from "./openai.js";
import type { LLMProvider } from "./types.js";

let anthropic: AnthropicProvider | null = null;
let openai: OpenAIProvider | null = null;

function init() {
  if (anthropic && openai) return;
  const env = loadEnv();
  anthropic = new AnthropicProvider(env.ANTHROPIC_API_KEY);
  openai = new OpenAIProvider(env.OPENAI_API_KEY);
}

/** Resolve the provider for a model name; throw 503 if its key is missing. */
export function getProvider(model: string): LLMProvider {
  init();
  const provider: LLMProvider | null = model === "gpt-4o" ? openai : anthropic;
  if (!provider || !provider.ready()) {
    throw ProviderUnavailableError(`No API key configured for model "${model}"`);
  }
  return provider;
}

/** Readiness summary for /healthz. */
export function providerReadiness(): { anthropic: boolean; openai: boolean; any: boolean } {
  init();
  const a = anthropic!.ready();
  const o = openai!.ready();
  return { anthropic: a, openai: o, any: a || o };
}

export function resetProviders(): void { anthropic = null; openai = null; }
