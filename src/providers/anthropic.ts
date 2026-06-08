import Anthropic from "@anthropic-ai/sdk";
import type { LLMProvider, ProviderRequest, ProviderResponse } from "./types.js";

const MODEL_MAP: Record<string, string> = { "claude-3-5-sonnet": "claude-3-5-sonnet-latest" };

export class AnthropicProvider implements LLMProvider {
  name = "anthropic";
  private client: Anthropic | null;
  constructor(apiKey: string | undefined) {
    this.client = apiKey ? new Anthropic({ apiKey }) : null;
  }
  ready(): boolean { return this.client !== null; }
  async chat(req: ProviderRequest): Promise<ProviderResponse> {
    if (!this.client) throw new Error("Anthropic not configured");
    const resp = await this.client.messages.create({
      model: MODEL_MAP[req.model] ?? req.model,
      max_tokens: req.maxTokens,
      messages: req.messages.filter((m) => m.role !== "system").map((m) => ({ role: m.role as "user" | "assistant", content: m.content })),
    });
    const content = resp.content.map((b) => (b.type === "text" ? b.text : "")).join("");
    return { content, raw: resp };
  }
}
