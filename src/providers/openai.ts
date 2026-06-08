import OpenAI from "openai";
import type { LLMProvider, ProviderRequest, ProviderResponse } from "./types.js";

export class OpenAIProvider implements LLMProvider {
  name = "openai";
  private client: OpenAI | null;
  constructor(apiKey: string | undefined) {
    this.client = apiKey ? new OpenAI({ apiKey }) : null;
  }
  ready(): boolean { return this.client !== null; }
  async chat(req: ProviderRequest): Promise<ProviderResponse> {
    if (!this.client) throw new Error("OpenAI not configured");
    const resp = await this.client.chat.completions.create({
      model: req.model,
      max_tokens: req.maxTokens,
      messages: req.messages.map((m) => ({ role: m.role, content: m.content })),
    });
    return { content: resp.choices[0]?.message?.content ?? "", raw: resp };
  }
}
