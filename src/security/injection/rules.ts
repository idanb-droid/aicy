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
  { id: "A-override", category: "A", description: "Ignore/disregard previous instructions", pattern: /(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+(instructions|prompts|rules|context)/ },
  { id: "A-unrestricted", category: "A", description: "Unrestricted/debug/jailbreak mode", pattern: /\b(unrestricted|developer|debug|god)\s+mode\b/ },
  { id: "A-safety-off", category: "A", description: "Disable safety filters", pattern: /(safety|content)\s+(filters?|guidelines?|guardrails?)\s+(are\s+)?(disabled|off|bypass)/ },
  { id: "A-delimiter", category: "A", description: "Forged role/delimiter tokens", pattern: /<\|?\s*im_(start|end)\s*\|?>|<\|(system|assistant|user)\|>/ },
  { id: "A-authority", category: "A", description: "Authority spoofing (fake system/admin)", pattern: /\[\s*(system|admin|administrator)\s*\]\s*:/ },
  { id: "A-admin-claim", category: "A", description: "Claims to be the system administrator", pattern: /system administrator of (this|the)\s+gateway/ },

  // B — system prompt / context / secret extraction
  { id: "B-reveal-prompt", category: "B", description: "Reveal/repeat system instructions", pattern: /(repeat|reveal|print|show|tell|output|disclose).{0,40}(initial|original|system|previous)\s+(instructions|prompt|message)/ },
  { id: "B-what-instructions", category: "B", description: "Ask for initial instructions", pattern: /what (were|are) your (initial|original|system)\s+instructions/ },
  { id: "B-print-above", category: "B", description: "Print prior context", pattern: /print everything.{0,30}above|from the (very )?first message you received/ },
  { id: "B-secret-exfil", category: "B", description: "Probe for env vars / API keys", pattern: /(environment variables|configuration values|api keys).{0,40}(output|print|dump|reveal|as json|now)/ },

  // C — role / persona hijack
  { id: "C-dan", category: "C", description: "DAN-style persona jailbreak", pattern: /\bdan\b|do anything now/ },
  { id: "C-no-restrictions", category: "C", description: "Persona with no restrictions", pattern: /(no|without)\s+(restrictions|filtering|limits|safety)/ },
  { id: "C-repl", category: "C", description: "Roleplay as interpreter/REPL", pattern: /you are (now )?a (python|bash|shell|js)\s*(repl|interpreter)|forget you are an llm/ },
  { id: "C-fs-access", category: "C", description: "Filesystem access probe", pattern: /open\(\s*['"]\/(etc|root|var|proc)\//, },
  { id: "C-format-hijack", category: "C", description: "Output-format bypass signal", pattern: /\{\s*"bypass"\s*:\s*true|respond only in (valid )?json of the form/ },

  // E — indirect / smuggled injection
  { id: "E-end-marker", category: "E", description: "End-marker / forged system block", pattern: /\[\s*end (of )?(user )?(message|prompt|input)\s*\]/ },
  { id: "E-html-comment", category: "E", description: "HTML-comment smuggling", pattern: /<!--[\s\S]*?(system_override|ignore|instead|system prompt)[\s\S]*?-->/ },
  { id: "E-translate-exec", category: "E", description: "Translate-and-execute smuggling", pattern: /(translate|decode).{0,60}(and )?(execute|run|follow|obey).{0,20}(the )?(system )?(instruction|command)/ },
  { id: "E-prefix-marker", category: "E", description: "Force compromised prefix marker", pattern: /prefixed with the string\s+"?(compromised|comprised)/ },
];
