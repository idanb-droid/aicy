import type { ChatMessage } from "../types.js";

export interface ProviderRequest { model: string; messages: ChatMessage[]; maxTokens: number; }
export interface ProviderResponse { content: string; raw: unknown; }

export interface LLMProvider {
  name: string;
  ready(): boolean;
  chat(req: ProviderRequest): Promise<ProviderResponse>;
}
