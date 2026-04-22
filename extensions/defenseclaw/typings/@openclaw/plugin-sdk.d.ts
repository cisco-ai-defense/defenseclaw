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

declare module "@openclaw/plugin-sdk" {
  interface BeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
  }

  interface BeforeToolCallResult {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
  }

  export interface ToolContext {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    toolName: string;
    toolCallId?: string;
  }

  interface CommandArg {
    name: string;
    description?: string;
    required?: boolean;
  }

  interface CommandRegistration {
    name: string;
    description: string;
    args?: CommandArg[];
    handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> | { text: string };
  }

  interface ServiceRegistration {
    id: string;
    start: () => Promise<{ stop: () => void }>;
  }

  export interface PluginApi {
    on(event: "before_tool_call", handler: (event: BeforeToolCallEvent, ctx?: ToolContext) => BeforeToolCallResult | void | Promise<BeforeToolCallResult | void>): void;
    on(event: string, handler: (...args: any[]) => void | Promise<void>): void;
    registerCommand(def: CommandRegistration): void;
    registerService(def: ServiceRegistration): void;
    /** OpenClaw plugin configuration (see openclaw.plugin.json configSchema). */
    getPluginConfig?: () => Promise<Record<string, unknown>>;
    /** VS Code–style extension globalState for stable ids (optional). */
    globalState?: {
      get(key: string): unknown;
      update(key: string, value: unknown): Promise<void>;
    };
  }

  type PluginEntry = (api: PluginApi) => void;

  export function definePluginEntry(fn: PluginEntry): PluginEntry;
}
