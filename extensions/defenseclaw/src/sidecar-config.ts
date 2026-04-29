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
const DEFAULT_TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN";

interface SidecarConfig {
  host: string;
  apiPort: number;
  baseUrl: string;
  token: string;
  guardrailPort: number;
  approvalTimeoutS: number;
  hiltEnabled: boolean;
}

let cached: SidecarConfig | undefined;

/**
 * Read gateway.host, gateway.api_port, and gateway token from
 * ~/.defenseclaw/config.yaml. Token resolution mirrors the Go sidecar:
 * env var (gateway.token_env, default OPENCLAW_GATEWAY_TOKEN) wins over
 * the direct gateway.token value. Falls back to defaults if the file is
 * missing or malformed. Result is cached for the lifetime of the process.
 */
export function loadSidecarConfig(): SidecarConfig {
  if (cached) return cached;

  let host = DEFAULT_HOST;
  let apiPort = DEFAULT_API_PORT;
  let guardrailPort = 4000;
  let approvalTimeoutS = 30;
  let hiltEnabled = false;
  let token = "";

  try {
    const cfgPath = join(homedir(), ".defenseclaw", "config.yaml");
    const raw = yaml.load(readFileSync(cfgPath, "utf8")) as Record<string, unknown> | null;
    if (raw && typeof raw === "object") {
      const gw = raw["gateway"] as Record<string, unknown> | undefined;
      if (gw && typeof gw === "object") {
        if (typeof gw["host"] === "string" && gw["host"]) host = gw["host"];
        if (typeof gw["api_port"] === "number") apiPort = gw["api_port"];
        if (typeof gw["approval_timeout_s"] === "number" && gw["approval_timeout_s"] > 0) {
          approvalTimeoutS = gw["approval_timeout_s"];
        }
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
        const hilt =
          (gr["hilt"] as Record<string, unknown> | undefined) ??
          (gr["hitl"] as Record<string, unknown> | undefined);
        if (hilt && typeof hilt === "object" && typeof hilt["enabled"] === "boolean") {
          hiltEnabled = hilt["enabled"];
        }
      }
    }
  } catch {
    // Config missing or unreadable — use defaults
  }

  if (!token) {
    const envVal = process.env[DEFAULT_TOKEN_ENV];
    if (envVal) token = envVal;
  }

  if (!token) {
    token = readDotEnvToken(DEFAULT_TOKEN_ENV);
  }

  cached = {
    host,
    apiPort,
    baseUrl: `http://${host}:${apiPort}`,
    token,
    guardrailPort,
    approvalTimeoutS,
    hiltEnabled,
  };
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
}
