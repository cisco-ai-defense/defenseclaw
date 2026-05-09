/*
 * Compound filter syntax used by the TUI's Audit and Alerts panels:
 *
 *   action=verdict severity>=high target_contains=github actor=remo
 *
 * Each token is `key=value`, `key:value`, `key>=value`, `key<=value`,
 * `key!=value`, or a bare keyword (substring match across all text fields).
 * Quotes are not honored — values are space-delimited.
 */

const SEV_RANK: Record<string, number> = {
  INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
};

export interface AuditEvent {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  actor: string;
  details: string;
  severity: string;
  run_id?: string;
  trace_id?: string;
  request_id?: string;
  session_id?: string;
  agent_name?: string;
  policy_id?: string;
  destination_app?: string;
  tool_name?: string;
  tool_id?: string;
  [k: string]: unknown;
}

interface Term {
  key: string | null;
  op: "=" | "!=" | ">=" | "<=" | ":";
  value: string;
}

const OPS = ["!=", ">=", "<=", "=", ":"] as const;

export function parseFilter(input: string): Term[] {
  const tokens = input.trim().split(/\s+/).filter(Boolean);
  const out: Term[] = [];
  for (const tok of tokens) {
    let matched: Term | null = null;
    for (const op of OPS) {
      const idx = tok.indexOf(op);
      if (idx > 0) {
        matched = {
          key: tok.slice(0, idx).toLowerCase(),
          op,
          value: tok.slice(idx + op.length),
        };
        break;
      }
    }
    out.push(matched ?? { key: null, op: ":", value: tok });
  }
  return out;
}

export function applyFilter(events: AuditEvent[], terms: Term[]): AuditEvent[] {
  if (terms.length === 0) return events;
  return events.filter((e) => terms.every((t) => match(e, t)));
}

function match(e: AuditEvent, t: Term): boolean {
  // Bare keyword → substring match across all rendered text.
  if (t.key === null) {
    const haystack = `${e.action} ${e.target} ${e.actor} ${e.details} ${e.severity} ${e.run_id ?? ""} ${e.trace_id ?? ""} ${e.policy_id ?? ""} ${e.tool_name ?? ""}`.toLowerCase();
    return haystack.includes(t.value.toLowerCase());
  }
  // Severity is the only field with a >= / <= ordering.
  if (t.key === "severity" && (t.op === ">=" || t.op === "<=")) {
    const a = SEV_RANK[(e.severity ?? "").toUpperCase()] ?? 0;
    const b = SEV_RANK[t.value.toUpperCase()] ?? 0;
    return t.op === ">=" ? a >= b : a <= b;
  }
  // *_contains is a sugar form for substring on the matching field.
  if (t.key.endsWith("_contains")) {
    const field = t.key.slice(0, -"_contains".length);
    const v = String((e as Record<string, unknown>)[field] ?? "");
    return v.toLowerCase().includes(t.value.toLowerCase());
  }
  const v = String((e as Record<string, unknown>)[t.key] ?? "");
  switch (t.op) {
    case "=":
    case ":":
      return v.toLowerCase() === t.value.toLowerCase();
    case "!=":
      return v.toLowerCase() !== t.value.toLowerCase();
    case ">=":
    case "<=":
      // No numeric comparison for arbitrary fields.
      return false;
  }
}
