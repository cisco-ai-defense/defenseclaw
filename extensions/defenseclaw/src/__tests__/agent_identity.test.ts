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

import { afterEach, describe, expect, it } from "vitest";
import {
  STABLE_AGENT_ID_STORAGE_KEY,
  bootstrapPluginIdentity,
  createGlobalStateStorage,
  createInMemoryStorage,
  getOrCreateStableAgentId,
  mintSessionAgentInstanceId,
  resolveOutboundAgentId,
} from "../agent_identity.js";

describe("getOrCreateStableAgentId", () => {
  it("mints and persists across reads", async () => {
    const storage = createInMemoryStorage();
    const a = await getOrCreateStableAgentId(storage, () => "uuid-a");
    const b = await getOrCreateStableAgentId(storage, () => "uuid-b");
    expect(a).toBe("uuid-a");
    expect(b).toBe("uuid-a");
  });

  it("uses vscode-like globalState", async () => {
    const store = new Map<string, unknown>();
    const gs = {
      get: (k: string) => store.get(k),
      update: async (k: string, v: unknown) => {
        store.set(k, v);
      },
    };
    const storage = createGlobalStateStorage(gs);
    const id = await getOrCreateStableAgentId(storage, () => "persisted-1");
    expect(id).toBe("persisted-1");
    expect(store.get(STABLE_AGENT_ID_STORAGE_KEY)).toBe("persisted-1");
  });
});

describe("resolveOutboundAgentId", () => {
  afterEach(() => {
    delete process.env.DEFENSECLAW_AGENT_ID;
    delete process.env.DEFENSECLAW_PLUGIN_AGENT_ID;
  });

  it("prefers DEFENSECLAW_AGENT_ID over config and stable", () => {
    process.env.DEFENSECLAW_AGENT_ID = "env-agent";
    expect(
      resolveOutboundAgentId({
        configAgentId: "cfg",
        stableAgentId: "stable",
      }),
    ).toBe("env-agent");
  });

  it("prefers DEFENSECLAW_PLUGIN_AGENT_ID when DEFENSECLAW_AGENT_ID unset", () => {
    process.env.DEFENSECLAW_PLUGIN_AGENT_ID = "plugin-env";
    expect(
      resolveOutboundAgentId({
        stableAgentId: "stable",
      }),
    ).toBe("plugin-env");
  });

  it("uses config when no env", () => {
    expect(
      resolveOutboundAgentId({
        configAgentId: "cfg-id",
        stableAgentId: "stable",
      }),
    ).toBe("cfg-id");
  });

  it("falls back to stable id", () => {
    expect(
      resolveOutboundAgentId({
        stableAgentId: "stable-only",
      }),
    ).toBe("stable-only");
  });
});

describe("bootstrapPluginIdentity", () => {
  it("returns session instance id distinct from stable id", async () => {
    const r = await bootstrapPluginIdentity({
      storage: createInMemoryStorage(),
      getConfigAgentId: async () => undefined,
      mintUuid: () => "stable-uuid",
    });
    expect(r.stableAgentId).toBe("stable-uuid");
    expect(r.agentId).toBe("stable-uuid");
    expect(r.sessionAgentInstanceId).toBeTruthy();
    expect(r.sessionAgentInstanceId).not.toBe(r.stableAgentId);
  });

  it("uses config agent id for outbound agent id", async () => {
    const r = await bootstrapPluginIdentity({
      storage: createInMemoryStorage(),
      getConfigAgentId: async () => "from-config",
      mintUuid: () => "stable-uuid",
    });
    expect(r.agentId).toBe("from-config");
    expect(r.stableAgentId).toBe("stable-uuid");
  });
});

describe("mintSessionAgentInstanceId", () => {
  it("returns a non-empty string", () => {
    const a = mintSessionAgentInstanceId();
    const b = mintSessionAgentInstanceId();
    expect(a.length).toBeGreaterThan(10);
    expect(a).not.toBe(b);
  });
});
