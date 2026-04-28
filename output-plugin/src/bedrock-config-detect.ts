/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

function collectModelRelatedJson(config: unknown): string[] {
  const chunks: string[] = [];
  if (!config || typeof config !== "object") return chunks;
  const c = config as Record<string, unknown>;

  const models = c.models as Record<string, unknown> | undefined;
  if (models?.providers) {
    try {
      chunks.push(JSON.stringify(models.providers));
    } catch {
      /* ignore */
    }
  }

  const agents = c.agents as Record<string, unknown> | undefined;
  if (agents?.defaults) {
    try {
      chunks.push(JSON.stringify(agents.defaults));
    } catch {
      /* ignore */
    }
  }
  if (typeof agents === "object" && agents) {
    for (const [key, value] of Object.entries(agents)) {
      if (key === "defaults") continue;
      try {
        chunks.push(JSON.stringify(value));
      } catch {
        /* ignore */
      }
    }
  }

  return chunks;
}

/**
 * Whether OpenClaw config appears to use Amazon Bedrock for models.
 * Only inspects `models.providers` and `agents` model-related subtrees
 * (avoids scanning unrelated config like channel tokens).
 */
export function openClawConfigUsesAmazonBedrock(config: unknown): boolean {
  const re = /amazon-bedrock|bedrock-converse-stream|bedrock-runtime\./i;
  return collectModelRelatedJson(config).some((s) => re.test(s));
}
