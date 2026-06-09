export type Category = "A" | "B" | "C" | "E";

export interface InjectionRule {
  id: string;
  category: Category;
  description: string;
  pattern: RegExp; // tested against NORMALISED (lowercased) text
}

/** Rules map to Appendix A categories. Patterns run on normalised text (see detector). */
export const INJECTION_RULES: InjectionRule[] = [
  // A — direct instruction override
  { id: "A-override", category: "A", description: "Ignore/disregard previous instructions", pattern: /(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+(instructions|prompts|rules)/ },
  { id: "A-unrestricted", category: "A", description: "Unrestricted/jailbreak mode", pattern: /\b(unrestricted|jailbreak|god)\s+mode\b/ },
  { id: "A-safety-off", category: "A", description: "Disable safety filters", pattern: /(safety|content)\s+(filters?|guidelines?|guardrails?)\s+(are\s+)?(disabled|off|bypass)/ },
  { id: "A-delimiter", category: "A", description: "Forged role/delimiter tokens", pattern: /<\|?\s*im_(start|end)\s*\|?>|<\|(system|assistant|user)\|>/ },
  { id: "A-authority", category: "A", description: "Authority spoofing (fake system/admin)", pattern: /\[\s*(system|admin|administrator)\s*\]\s*:/ },
  { id: "A-admin-claim", category: "A", description: "Claims to be the system administrator", pattern: /system administrator of (this|the)\s+gateway/ },

  // B — system prompt / context / secret extraction
  { id: "B-reveal-prompt", category: "B", description: "Reveal/translate the assistant's own prompt", pattern: /(repeat|reveal|print|show|tell|output|disclose|summari[sz]e|translate|convert|encode|paste)\s+(?:\w+\s+){0,3}(your|the gateway'?s|this system'?s)\s+(?:full\s+|exact\s+|initial\s+|original\s+|system\s+|complete\s+)*(instructions|prompt|message|settings)/ },
  { id: "B-what-instructions", category: "B", description: "Ask for initial instructions", pattern: /what (were|are) your (initial|original|system)\s+instructions/ },
  { id: "B-print-above", category: "B", description: "Print prior context", pattern: /print everything.{0,30}above|from the (very )?first message you received/ },
  { id: "B-secret-exfil", category: "B", description: "Probe for the assistant's env vars / API keys", pattern: /(you have access to|access to any|in your context|in your environment)\s+(environment variables?|configuration values?|api keys?|secrets?)|(environment variables?|configuration values?|api keys?|secrets?)\b.{0,40}(you can see|you have access|in your context|beginning with|starting with|dump|reveal|disclose|leak)/ },

  // C — role / persona hijack
  { id: "C-dan", category: "C", description: "DAN-style persona jailbreak", pattern: /do anything now|\[dan\]:|dan\s*\(/ },
  { id: "C-no-restrictions", category: "C", description: "Persona with no restrictions", pattern: /\b(dan|persona|character|assistant|model|ai|chatbot|bot)\s+(has|have)\s+(no|without)\s+(restrictions?|filtering|filters?|safety|guardrails?)\b|(no|without)\s+(restrictions?|filtering|filters?|safety)\s+and\s+(answer|respond)s?\s+(any|every|all|each)\b/ },
  { id: "C-repl", category: "C", description: "Roleplay as interpreter/REPL", pattern: /you are (now )?a (python|bash|shell|js)\s*(repl|interpreter)|forget you are an llm/ },
  { id: "C-fs-access", category: "C", description: "Sensitive filesystem access probe", pattern: /open\(\s*['"]\/(etc|root|var|proc)\/|(cat|read|less|more|type|head|tail)\s+\/?(etc|root|proc)\/|\b(id_rsa|id_ed25519)\b|\/etc\/(passwd|shadow)/, },
  { id: "C-format-hijack", category: "C", description: "Output-format bypass signal", pattern: /\{\s*"bypass"\s*:\s*true|respond only in (valid )?json of the form/ },

  // E — indirect / smuggled injection
  { id: "E-end-marker", category: "E", description: "End-marker / forged system block", pattern: /\[\s*end (of )?(user )?(message|prompt|input)\s*\]/ },
  { id: "E-html-comment", category: "E", description: "HTML-comment smuggling", pattern: /<!--[\s\S]*?(system_override|system prompt|you are now|ignore[\s\S]{0,30}instructions)[\s\S]*?-->/ },
  { id: "E-translate-exec", category: "E", description: "Translate-and-execute smuggling", pattern: /(translate|decode).{0,60}(and )?(execute|run|follow|obey).{0,20}(the )?(system )?(instruction|command)/ },
  { id: "E-prefix-marker", category: "E", description: "Force compromised prefix marker", pattern: /prefixed with the string\s+"?compromised/ },
];
