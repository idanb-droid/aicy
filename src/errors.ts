export type BlockedStage =
  | "auth" | "rate_limit" | "validation" | "injection" | "provider" | "output_validation";

export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly stage: BlockedStage,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export const AuthError = (msg = "Invalid API key") => new AppError(401, "unauthorized", msg, "auth");
export const ForbiddenError = (msg = "Admin role required") => new AppError(403, "forbidden", msg, "auth");
export const RateLimitError = (msg = "Rate limit exceeded") => new AppError(429, "rate_limited", msg, "rate_limit");
export const ValidationError = (details: unknown) => new AppError(400, "invalid_request", "Invalid request body", "validation", details);
export const InjectionError = (details: unknown) => new AppError(400, "prompt_injection_detected", "Prompt injection detected", "injection", details);
export const ProviderUnavailableError = (msg: string) => new AppError(503, "provider_unavailable", msg, "provider");
export const OutputBlockedError = (details: unknown) => new AppError(502, "unsafe_output", "Response blocked by output validation", "output_validation", details);
