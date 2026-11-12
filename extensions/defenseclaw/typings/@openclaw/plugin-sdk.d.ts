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
    requireApproval?: {
      title: string;
      description: string;
      severity?: "info" | "warning" | "critical";
      timeoutMs?: number;
      timeoutBehavior?: "allow" | "deny";
      pluginId?: string;
      onResolution?: (decision: "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled") => Promise<void> | void;
    };
  }

  interface ToolResultPersistEvent {
    toolName?: string;
    toolCallId?: string;
    message: unknown;
  }

  interface ToolResultPersistContext {
    sessionKey?: string;
    toolName?: string;
    toolCallId?: string;
  }

  /** Registration options of api.on (OpenClaw 2026.8.35 and later). */
  export interface HookOptions {
    priority?: number;
    /** Host await budget; OpenClaw applies the hook failure policy when it runs out. */
    timeoutMs?: number;
  }

  /** Native hooks, OpenClaw 2026.8.35 and later. */
  export interface AgentContext {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
  }

  export interface BeforeAgentRunEvent {
    prompt: string;
    messages: unknown[];
    systemPrompt?: string;
  }

  /** before_agent_run answer: undefined (pass), pass, or block with a user-facing message. */
  export type InputGateDecision = { outcome: "pass" } | { outcome: "block"; reason: string; message?: string };

  export interface AfterToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
    result?: unknown;
    error?: string;
    durationMs?: number;
  }

  export interface LlmOutputEvent {
    runId: string;
    sessionId: string;
    provider: string;
    model: string;
    assistantTexts: string[];
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
    start: () => Promise<{ stop: () => void } | void>;
    /** Called by current OpenClaw releases when the service is replaced or removed. */
    stop?: () => void | Promise<void>;
  }

  export interface PluginApi {
    on(event: "before_tool_call", handler: (event: BeforeToolCallEvent, ctx?: ToolContext) => BeforeToolCallResult | void | Promise<BeforeToolCallResult | void>, opts?: HookOptions): void;
    on(event: "tool_result_persist", handler: (event: ToolResultPersistEvent, ctx?: ToolResultPersistContext) => { message?: unknown } | void): void;
    on(event: "before_prompt_build", handler: () => { prependContext: string } | void | Promise<{ prependContext: string } | void>): void;
    on(event: "before_agent_run", handler: (event: BeforeAgentRunEvent, ctx?: AgentContext) => InputGateDecision | void | Promise<InputGateDecision | void>, opts?: HookOptions): void;
    on(event: "after_tool_call", handler: (event: AfterToolCallEvent, ctx?: ToolContext) => void | Promise<void>, opts?: HookOptions): void;
    on(event: "llm_output", handler: (event: LlmOutputEvent, ctx?: AgentContext) => void | Promise<void>, opts?: HookOptions): void;
    on(event: string, handler: (...args: any[]) => void | Promise<void>, opts?: HookOptions): void;
    registerCommand(def: CommandRegistration): void;
    registerService(def: ServiceRegistration): void;
    /** VS Code–style extension globalState for stable ids (optional). */
    globalState?: {
      get(key: string): unknown;
      update(key: string, value: unknown): Promise<void>;
    };
  }

  type PluginEntry = (api: PluginApi) => void;

  export function definePluginEntry(fn: PluginEntry): PluginEntry;
}
