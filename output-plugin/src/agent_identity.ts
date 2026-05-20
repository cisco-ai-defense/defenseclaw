/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { randomUUID } from "node:crypto";

/** Extension `globalState` key for stable logical agent id across restarts. */
export const STABLE_AGENT_ID_STORAGE_KEY = "defenseclaw.plugin.stableAgentId";

export interface KeyValueStorage {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
}

export function createInMemoryStorage(
  seed?: Record<string, string>,
): KeyValueStorage {
  const map = new Map<string, string>(Object.entries(seed ?? {}));
  return {
    async get(key: string) {
      return map.get(key);
    },
    async set(key: string, value: string) {
      map.set(key, value);
    },
  };
}

/**
 * VS Code–compatible globalState adapter (OpenClaw may expose the same shape).
 */
export function createGlobalStateStorage(globalState: {
  get(key: string): unknown;
  update(key: string, value: unknown): Promise<void>;
}): KeyValueStorage {
  return {
    async get(key: string) {
      const v = globalState.get(key);
      return typeof v === "string" && v.length > 0 ? v : undefined;
    },
    set(key: string, value: string) {
      return globalState.update(key, value);
    },
  };
}

export function mintSessionAgentInstanceId(): string {
  return randomUUID();
}

/**
 * Returns a stable id persisted in extension storage, minting once if missing.
 */
export async function getOrCreateStableAgentId(
  storage: KeyValueStorage,
  mintUuid: () => string = randomUUID,
): Promise<string> {
  const existing = await storage.get(STABLE_AGENT_ID_STORAGE_KEY);
  if (existing) return existing;
  const created = mintUuid();
  await storage.set(STABLE_AGENT_ID_STORAGE_KEY, created);
  return created;
}

const ENV_AGENT_ID_KEYS = ["DEFENSECLAW_AGENT_ID", "DEFENSECLAW_PLUGIN_AGENT_ID"] as const;

function readEnvAgentId(): string | undefined {
  for (const k of ENV_AGENT_ID_KEYS) {
    const v = process.env[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

export interface ResolveOutboundAgentIdInput {
  /** OpenClaw plugin config `agent.id` (highest precedence after env). */
  configAgentId?: string;
  /** Persisted stable id from extension storage. */
  stableAgentId: string;
}

/**
 * Resolves the logical agent id for `X-DefenseClaw-Agent-Id`:
 * env override → plugin config `agent.id` → persisted stable id.
 */
export function resolveOutboundAgentId(input: ResolveOutboundAgentIdInput): string {
  const env = readEnvAgentId();
  if (env) return env;
  const cfg = input.configAgentId?.trim();
  if (cfg) return cfg;
  return input.stableAgentId;
}

export interface BootstrapPluginIdentityOptions {
  storage: KeyValueStorage;
  getConfigAgentId?: () => Promise<string | undefined>;
  mintUuid?: () => string;
}

export interface BootstrapPluginIdentityResult {
  agentId: string;
  stableAgentId: string;
  sessionAgentInstanceId: string;
}

/**
 * Called on plugin activation: persist stable id, mint session instance id, resolve outbound agent id.
 */
export async function bootstrapPluginIdentity(
  opts: BootstrapPluginIdentityOptions,
): Promise<BootstrapPluginIdentityResult> {
  const stableAgentId = await getOrCreateStableAgentId(
    opts.storage,
    opts.mintUuid ?? randomUUID,
  );
  const configAgentId = opts.getConfigAgentId
    ? await opts.getConfigAgentId()
    : undefined;
  const agentId = resolveOutboundAgentId({ configAgentId, stableAgentId });
  return {
    agentId,
    stableAgentId,
    sessionAgentInstanceId: mintSessionAgentInstanceId(),
  };
}
