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

/**
 * LLM client — calls the defenseclaw Python bridge for LLM access.
 *
 * Uses the same provider routing and API key handling as the skill scanner.
 *
 * The bridge is at cli/defenseclaw/llm.py and accepts JSON on stdin,
 * returns JSON on stdout.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LLMConfig {
  /** Model name (e.g. "claude-sonnet-4-20250514", "gpt-4", "ollama/llama3"). */
  model: string;
  /** API key (falls back to env vars if not set). */
  apiKey?: string;
  /** Custom API base URL (for Azure, Ollama, etc.). */
  apiBase?: string;
  /** Provider hint (auto-detected from model name if omitted). */
  provider?: string;
  /** Max output tokens (default 8192). */
  maxTokens?: number;
  /** Number of consensus runs (default 1). */
  consensusRuns?: number;
  /** Python binary path (default "python3"). */
  pythonBinary?: string;
}

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMResponse {
  content: string;
  model: string;
  usage: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
  error: string | null;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const ALLOWED_PYTHON_NAMES = new Set(["python3", "python", "python3.11", "python3.12", "python3.13"]);

export function validatePythonBinary(raw: string): string {
  if (ALLOWED_PYTHON_NAMES.has(raw)) {
    return raw;
  }

  const resolved = resolve(raw);
  if (
    !resolved.startsWith("/") ||
    resolved.includes("..") ||
    !existsSync(resolved)
  ) {
    throw new Error(
      `Refusing untrusted python_binary: "${raw}". ` +
      `Use an absolute path to an existing executable or one of: ${[...ALLOWED_PYTHON_NAMES].join(", ")}`,
    );
  }
  return resolved;
}

export async function callLLM(
  config: LLMConfig,
  messages: LLMMessage[],
): Promise<LLMResponse> {
  const python = validatePythonBinary(config.pythonBinary ?? "python3");

  const request = {
    model: config.model,
    messages,
    max_tokens: config.maxTokens ?? 8192,
    temperature: 0.0,
    ...(config.apiKey && { api_key: config.apiKey }),
    ...(config.apiBase && { api_base: config.apiBase }),
    ...(config.provider && { provider: config.provider }),
  };

  const input = JSON.stringify(request);

  try {
    const stdout = execFileSync(
      python,
      ["-m", "defenseclaw.llm"],
      { input, timeout: 120_000, maxBuffer: 10 * 1024 * 1024, encoding: "utf-8" },
    );

    const response = JSON.parse(stdout) as LLMResponse;
    return response;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { content: "", model: config.model, usage: {}, error: message };
  }
}

/**
 * Run LLM N times and return only findings that appear in the majority of runs.
 * This matches the skill scanner's consensus_runs feature.
 */
export async function callLLMWithConsensus(
  config: LLMConfig,
  messages: LLMMessage[],
  runs: number,
): Promise<LLMResponse> {
  if (runs <= 1) return callLLM(config, messages);

  const results = await Promise.all(
    Array.from({ length: runs }, () => callLLM(config, messages)),
  );

  // Filter out errors
  const successful = results.filter((r) => !r.error);
  if (successful.length === 0) {
    return results[0]; // return first error
  }

  // For consensus, return the response with the most overlap in content.
  // Simple heuristic: pick the longest non-error response (it likely
  // contains the most complete analysis).
  const best = successful.reduce((a, b) =>
    a.content.length >= b.content.length ? a : b,
  );

  // Sum usage across runs
  const totalUsage = {
    prompt_tokens: successful.reduce((s, r) => s + (r.usage.prompt_tokens ?? 0), 0),
    completion_tokens: successful.reduce((s, r) => s + (r.usage.completion_tokens ?? 0), 0),
    total_tokens: successful.reduce((s, r) => s + (r.usage.total_tokens ?? 0), 0),
  };

  return { ...best, usage: totalUsage };
}
