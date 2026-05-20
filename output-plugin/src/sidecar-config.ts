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

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import yaml from "js-yaml";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_API_PORT = 18970;
const DEFAULT_GUARDRAIL_PORT = 4000;
const DEFAULT_TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN";

interface SidecarConfig {
  host: string;
  apiPort: number;
  baseUrl: string;
  token: string;
  guardrailPort: number;
}

/**
 * Overrides from the OpenClaw plugin configSchema (ClawHub settings UI).
 * These take highest precedence when provided.
 */
export interface SidecarConfigOverrides {
  host?: string;
  apiPort?: number;
  guardrailPort?: number;
}

let cached: SidecarConfig | undefined;
let cachedOverridesKey: string | undefined;

function overridesKey(o?: SidecarConfigOverrides): string {
  if (!o) return "";
  return `${o.host ?? ""}:${o.apiPort ?? ""}:${o.guardrailPort ?? ""}`;
}

/**
 * Resolves sidecar connection config with a 3-tier precedence:
 *
 * 1. Plugin config overrides (from ClawHub settings UI / openclaw.plugin.json)
 * 2. Environment variables (DEFENSECLAW_HOST, DEFENSECLAW_PORT, DEFENSECLAW_GUARDRAIL_PORT)
 * 3. ~/.defenseclaw/config.yaml (if present on the host)
 * 4. Hardcoded defaults (127.0.0.1:18970, guardrail 4000)
 *
 * Token resolution mirrors the Go sidecar:
 * env var (gateway.token_env, default OPENCLAW_GATEWAY_TOKEN) wins over
 * the direct gateway.token value.
 *
 * Result is cached for the lifetime of the process (cache is invalidated
 * if overrides change).
 */
export function loadSidecarConfig(overrides?: SidecarConfigOverrides): SidecarConfig {
  const key = overridesKey(overrides);
  if (cached && cachedOverridesKey === key) return cached;

  let host = DEFAULT_HOST;
  let apiPort = DEFAULT_API_PORT;
  let guardrailPort = DEFAULT_GUARDRAIL_PORT;
  let token = "";

  // Tier 3: ~/.defenseclaw/config.yaml
  try {
    const cfgPath = join(homedir(), ".defenseclaw", "config.yaml");
    const raw = yaml.load(readFileSync(cfgPath, "utf8")) as Record<string, unknown> | null;
    if (raw && typeof raw === "object") {
      const gw = raw["gateway"] as Record<string, unknown> | undefined;
      if (gw && typeof gw === "object") {
        if (typeof gw["host"] === "string" && gw["host"]) host = gw["host"];
        if (typeof gw["api_port"] === "number") apiPort = gw["api_port"];
        if (typeof gw["token"] === "string" && gw["token"]) token = gw["token"];
        const tokenEnv =
          typeof gw["token_env"] === "string" && gw["token_env"]
            ? gw["token_env"]
            : DEFAULT_TOKEN_ENV;
        const envVal = process.env[tokenEnv];
        if (envVal) token = envVal;
      }
      const gr = raw["guardrail"] as Record<string, unknown> | undefined;
      if (gr && typeof gr === "object") {
        if (typeof gr["port"] === "number") guardrailPort = gr["port"];
      }
    }
  } catch {
    // Config missing or unreadable — use defaults
  }

  // Tier 2: Environment variables
  const envHost = process.env.DEFENSECLAW_HOST;
  if (typeof envHost === "string" && envHost) host = envHost;

  const envPort = process.env.DEFENSECLAW_PORT;
  if (typeof envPort === "string" && envPort) {
    const parsed = parseInt(envPort, 10);
    if (Number.isFinite(parsed) && parsed > 0) apiPort = parsed;
  }

  const envGuardrailPort = process.env.DEFENSECLAW_GUARDRAIL_PORT;
  if (typeof envGuardrailPort === "string" && envGuardrailPort) {
    const parsed = parseInt(envGuardrailPort, 10);
    if (Number.isFinite(parsed) && parsed > 0) guardrailPort = parsed;
  }

  // Tier 1: Plugin config overrides (highest precedence)
  if (overrides?.host) host = overrides.host;
  if (overrides?.apiPort) apiPort = overrides.apiPort;
  if (overrides?.guardrailPort) guardrailPort = overrides.guardrailPort;

  // Token fallbacks (same as embedded plugin)
  if (!token) {
    const envVal = process.env[DEFAULT_TOKEN_ENV];
    if (envVal) token = envVal;
  }

  if (!token) {
    token = readDotEnvToken(DEFAULT_TOKEN_ENV);
  }

  cached = { host, apiPort, baseUrl: `http://${host}:${apiPort}`, token, guardrailPort };
  cachedOverridesKey = key;
  return cached;
}

/**
 * Read a KEY=VALUE token from ~/.defenseclaw/.env.
 * The Go sidecar loads this file into its own process env, but the
 * OpenClaw Node.js process is separate and won't have it.
 */
function readDotEnvToken(key: string): string {
  try {
    const envPath = join(homedir(), ".defenseclaw", ".env");
    const content = readFileSync(envPath, "utf8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;
      const eqIdx = trimmed.indexOf("=");
      const k = trimmed.slice(0, eqIdx).trim();
      if (k === key) {
        return trimmed.slice(eqIdx + 1).trim();
      }
    }
  } catch {
    // .env missing or unreadable
  }
  return "";
}

/** Clear cached config (for testing). */
export function _resetSidecarConfigCache(): void {
  cached = undefined;
  cachedOverridesKey = undefined;
}
