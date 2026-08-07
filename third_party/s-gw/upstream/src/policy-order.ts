import type { ApprovalPolicyDecision, SecretSeverity } from "./types.js";

export interface PolicyConditionsLike {
  handles?: string[];
  envBindings?: Array<{ handle: string; injectEnv: string }>;
  secretTypes?: string[];
  providers?: string[];
  minSeverity?: SecretSeverity;
  agents?: string[];
  actionKinds?: string[];
  commands?: string[];
  resolvedCommands?: string[];
  injectEnvs?: string[];
  workingDirs?: string[];
  sshTargets?: string[];
  sshPorts?: number[];
}

export interface PolicyRuleLike {
  id: string;
  priority: number;
  decision: ApprovalPolicyDecision;
  conditions: PolicyConditionsLike;
  enabled: boolean;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}

const arrayFields: Array<keyof Pick<
  PolicyConditionsLike,
  "handles" | "secretTypes" | "providers" | "agents" | "actionKinds" | "commands" | "resolvedCommands" | "injectEnvs" | "workingDirs" | "sshTargets" | "sshPorts"
>> = [
  "handles",
  "secretTypes",
  "providers",
  "agents",
  "actionKinds",
  "commands",
  "resolvedCommands",
  "injectEnvs",
  "workingDirs",
  "sshTargets",
  "sshPorts"
];

const severityRanks: Record<SecretSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
};

const decisionRanks: Record<ApprovalPolicyDecision, number> = {
  deny: 0,
  ask: 1,
  allow: 2
};

export function compareApprovalPolicyRules<T extends PolicyRuleLike>(left: T, right: T): number {
  const priority = left.priority - right.priority;
  if (priority) {
    return priority;
  }

  const updated = right.updatedAt.localeCompare(left.updatedAt);
  return updated || left.id.localeCompare(right.id);
}

export function approvalPolicyRuleCovers<T extends PolicyRuleLike>(broader: T, narrower: T): boolean {
  if (!bindingSetCovers(broader.conditions.envBindings, narrower.conditions.envBindings)) {
    return false;
  }
  if (broader.decision === "allow" && !broader.conditions.resolvedCommands?.length &&
      narrower.conditions.resolvedCommands?.length) {
    return false;
  }

  for (const field of arrayFields) {
    if (!listCovers(broader.conditions[field], narrower.conditions[field])) {
      return false;
    }
  }

  const broaderSeverity = broader.conditions.minSeverity;
  const narrowerSeverity = narrower.conditions.minSeverity;
  if (broaderSeverity && (!narrowerSeverity || severityRanks[broaderSeverity] > severityRanks[narrowerSeverity])) {
    return false;
  }

  return true;
}

export function approvalPolicyRulesEquivalent<T extends PolicyRuleLike>(left: T, right: T): boolean {
  return approvalPolicyRuleCovers(left, right) && approvalPolicyRuleCovers(right, left);
}

export function findShadowingPolicyRule<T extends PolicyRuleLike>(
  rules: T[],
  target: T,
  now = new Date().toISOString()
): T | undefined {
  for (const candidate of [...rules].sort(compareApprovalPolicyRules)) {
    if (candidate.id === target.id) {
      break;
    }
    if (!candidate.enabled || isExpired(candidate, now)) {
      continue;
    }
    if (approvalPolicyRuleCovers(candidate, target)) {
      return candidate;
    }
  }

  return undefined;
}

export function arrangeApprovalPolicyRules<T extends PolicyRuleLike>(
  rules: T[],
  now = new Date().toISOString()
): { rules: T[]; reordered: number } {
  const current = [...rules].sort(compareApprovalPolicyRules);
  const originalIndex = new Map(current.map((rule, index) => [rule.id, index] as const));
  const outgoing = new Map<string, Set<string>>(current.map((rule) => [rule.id, new Set<string>()]));
  const indegree = new Map<string, number>(current.map((rule) => [rule.id, 0]));

  for (const left of current) {
    for (const right of current) {
      if (left.id === right.id) {
        continue;
      }

      if (approvalPolicyRuleCovers(left, right) && !approvalPolicyRuleCovers(right, left)) {
        if (left.decision === "deny" && right.decision !== "deny") {
          addOrderConstraint(outgoing, indegree, left.id, right.id);
        } else {
          addOrderConstraint(outgoing, indegree, right.id, left.id);
        }
        continue;
      }

      if (!approvalPolicyRulesEquivalent(left, right)) {
        continue;
      }

      if (decisionRanks[left.decision] < decisionRanks[right.decision]) {
        addOrderConstraint(outgoing, indegree, left.id, right.id);
      }
    }
  }

  const byId = new Map(current.map((rule) => [rule.id, rule] as const));
  const ready = current.filter((rule) => indegree.get(rule.id) === 0);
  const arranged: T[] = [];

  while (ready.length) {
    ready.sort((left, right) => (originalIndex.get(left.id) || 0) - (originalIndex.get(right.id) || 0));
    const next = ready.shift();
    if (!next) {
      break;
    }
    arranged.push(next);

    for (const childId of outgoing.get(next.id) || []) {
      const nextIndegree = (indegree.get(childId) || 0) - 1;
      indegree.set(childId, nextIndegree);
      if (nextIndegree === 0) {
        const child = byId.get(childId);
        if (child) {
          ready.push(child);
        }
      }
    }
  }

  if (arranged.length !== current.length) {
    return { rules: current, reordered: 0 };
  }

  const reordered = arranged.filter((rule, index) => current[index]?.id !== rule.id).length;
  if (reordered === 0) {
    return { rules: current, reordered };
  }

  return {
    rules: arranged.map((rule, index) => ({
      ...rule,
      priority: (index + 1) * 10,
      updatedAt: now
    })),
    reordered
  };
}

function addOrderConstraint(
  outgoing: Map<string, Set<string>>,
  indegree: Map<string, number>,
  beforeId: string,
  afterId: string
): void {
  const children = outgoing.get(beforeId);
  if (!children || children.has(afterId)) {
    return;
  }

  children.add(afterId);
  indegree.set(afterId, (indegree.get(afterId) || 0) + 1);
}

function listCovers(broader: unknown[] | undefined, narrower: unknown[] | undefined): boolean {
  if (!broader?.length) {
    return true;
  }
  if (!narrower?.length) {
    return false;
  }

  const values = new Set(broader);
  return narrower.every((value) => values.has(value));
}

function bindingSetCovers(
  broader: Array<{ handle: string; injectEnv: string }> | undefined,
  narrower: Array<{ handle: string; injectEnv: string }> | undefined
): boolean {
  if (!broader?.length) {
    return true;
  }
  if (!narrower?.length || broader.length !== narrower.length) {
    return false;
  }

  const values = new Set(broader.map((binding) => `${binding.handle}\u0000${binding.injectEnv}`));
  return narrower.every((binding) => values.has(`${binding.handle}\u0000${binding.injectEnv}`));
}

function isExpired(rule: PolicyRuleLike, now: string): boolean {
  return Boolean(rule.expiresAt && rule.expiresAt <= now);
}
