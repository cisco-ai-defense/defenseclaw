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
// DEFENSECLAW_GATEWAY_TOKEN is the canonical env-var name written by
// the Go sidecar's first-boot bootstrap path. OPENCLAW_GATEWAY_TOKEN
// is preserved as a legacy fallback for installs that pre-date the
// rename. Lookup order is consistent across process.env AND ~/.defenseclaw/.env.
const DEFAULT_TOKEN_ENV = "DEFENSECLAW_GATEWAY_TOKEN";
const LEGACY_TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN";

interface SidecarConfig {
  host: string;
  apiPort: number;
  baseUrl: string;
  token: string;
  guardrailPort: number;
  approvalTimeoutS: number;
  hiltEnabled: boolean;
  /**
   * Mirror of guardrail.mode from ~/.defenseclaw/config.yaml. Values
   * recognised by the host enforcement code are:
   *   - "observe" (default): inspection failures fall open (legacy
   *     behaviour, used in development).
   *   - "action" / "enforce": inspection failures fail CLOSED. The
   *     extension MUST NOT silently allow tool calls when the sidecar
   *     is unreachable, returns 401/403/413, times out, or returns
   *     malformed JSON (finding "Tool inspection fails open
   *     on sidecar errors").
   * Anything else is treated as observe to preserve the existing
   * conservative default for unknown values.
   */
  enforcementMode: "observe" | "action";
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
  // Default to observe to keep current dev behaviour. Production
  // installs flip this via `guardrail.mode = action` (or `enforce`).
  let enforcementMode: "observe" | "action" = "observe";

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
        // Mirror the Go resolver: try process.env first, then the
        // sidecar-managed ~/.defenseclaw/.env. The .env path is the
        // common case in production because the Go bootstrap writes
        // DEFENSECLAW_GATEWAY_TOKEN there but does not export it
        // into the Node process that loads this extension.
        const envVal = process.env[tokenEnv] || readDotEnvToken(tokenEnv);
        if (envVal) token = envVal;
      }
      const gr = raw["guardrail"] as Record<string, unknown> | undefined;
      if (gr && typeof gr === "object") {
        if (typeof gr["port"] === "number") guardrailPort = gr["port"];
        if (typeof gr["mode"] === "string") {
          const m = gr["mode"].toLowerCase();
          // "action" and "enforce" are accepted aliases for the
          // fail-closed behaviour. Anything else (including the legacy
          // empty string) stays in observe.
          enforcementMode = m === "action" || m === "enforce" ? "action" : "observe";
        }
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

  // Last-resort fallbacks: try the canonical name, then the legacy
  // OPENCLAW_GATEWAY_TOKEN. Both process.env and ~/.defenseclaw/.env
  // are consulted for each name so the resolver works regardless of
  // whether the operator exported the value into the shell or kept
  // it solely in the sidecar-managed dotenv.
  for (const name of [DEFAULT_TOKEN_ENV, LEGACY_TOKEN_ENV]) {
    if (token) break;
    const envVal = process.env[name];
    if (envVal) {
      token = envVal;
      break;
    }
    const dotenvVal = readDotEnvToken(name);
    if (dotenvVal) {
      token = dotenvVal;
      break;
    }
  }

  cached = {
    host,
    apiPort,
    baseUrl: `http://${host}:${apiPort}`,
    token,
    guardrailPort,
    approvalTimeoutS,
    hiltEnabled,
    enforcementMode,
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
