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

import { readFileSync, statSync } from "node:fs";
import { isAbsolute, join, normalize } from "node:path";
import { homedir, userInfo } from "node:os";
import { execFileSync } from "node:child_process";
import yaml from "js-yaml";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_API_PORT = 18970;
// The plugin credential: the connector-scoped hook token setup mints for
// openclaw. It authenticates only the routes the plugin calls
// (internal/gateway/openclaw_plugin_scope.go), never the management API.
// Before 1.0.10 the plugin read the master gateway token from config.yaml,
// .env or OPENCLAW_GATEWAY_TOKEN; it reads none of them now.
const PLUGIN_TOKEN_FILE = join("hooks", ".hook-openclaw.token");
const PLUGIN_TOKEN_RE = /^[0-9a-f]{64}$/;

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
let cachedKey = "";

/** Resolve the exact DefenseClaw data root selected by the host process. */
function resolveDefenseClawHome(): string {
  const override = process.env.DEFENSECLAW_HOME;
  if (override === undefined || override === "") {
    return join(homedir(), ".defenseclaw");
  }
  if (!isAbsolute(override)) {
    throw new Error("DEFENSECLAW_HOME must be an absolute path");
  }
  return normalize(override);
}

/**
 * Read gateway.host and gateway.api_port from ~/.defenseclaw/config.yaml
 * and the plugin credential from hooks/.hook-openclaw.token. Falls back to
 * defaults if config.yaml is missing or malformed. The result is cached
 * until config.yaml or the credential file changes: setup and token
 * rotation rewrite the credential while OpenClaw keeps running, and a
 * stale one fails every sidecar call (GAP-2286).
 */
/**
 * The separate-user layout: the OpenClaw account cannot read the DefenseClaw
 * data folder, so plugins.entries.defenseclaw.config names the gateway
 * address and the published credential (tokenFile), and the guardrail
 * settings come from GET /api/v1/openclaw/runtime (setRuntimeSettings).
 */
interface SidecarConnection {
  tokenFile: string;
  host: string;
  apiPort: number;
  guardrailPort: number;
}

let connection: SidecarConnection | undefined;
let runtimeSettings = { hiltEnabled: false, approvalTimeoutS: 30 };

/** Configure the separate-user layout from api.pluginConfig (no tokenFile: off). */
export function configureSidecarConnection(pluginConfig: unknown): void {
  const pc = (pluginConfig ?? {}) as Record<string, unknown>;
  const tokenFile = typeof pc["tokenFile"] === "string" ? pc["tokenFile"] : "";
  if (!tokenFile || !isAbsolute(tokenFile)) {
    connection = undefined;
  } else {
    const num = (v: unknown, d: number) => (typeof v === "number" && v > 0 ? v : d);
    connection = {
      tokenFile: normalize(tokenFile),
      host: typeof pc["sidecarHost"] === "string" && pc["sidecarHost"] ? pc["sidecarHost"] : DEFAULT_HOST,
      apiPort: num(pc["sidecarPort"], DEFAULT_API_PORT),
      guardrailPort: num(pc["guardrailPort"], 4000),
    };
  }
  _resetSidecarConfigCache();
}

/** Whether the plugin runs in the separate-user layout. */
export function separateUserLayout(): boolean {
  return connection !== undefined;
}

/** Apply the answer of GET /api/v1/openclaw/runtime (separate-user layout). */
export function setRuntimeSettings(answer: unknown): void {
  const a = (answer ?? {}) as Record<string, unknown>;
  runtimeSettings = {
    hiltEnabled: a["hilt_enabled"] === true,
    approvalTimeoutS:
      typeof a["approval_timeout_s"] === "number" && a["approval_timeout_s"] > 0 ? a["approval_timeout_s"] : 30,
  };
  _resetSidecarConfigCache();
}

function readTokenFile(path: string): string {
  try {
    const value = readFileSync(path, "utf8").trim();
    return PLUGIN_TOKEN_RE.test(value) ? value : "";
  } catch {
    return "";
  }
}

function tokenFileKey(path: string): string {
  try {
    const st = statSync(path);
    return `${path}:${st.mtimeMs}:${st.size}`;
  } catch {
    return `${path}:missing`;
  }
}

export function loadSidecarConfig(): SidecarConfig {
  if (connection) {
    const key = `separate|${tokenFileKey(connection.tokenFile)}|${runtimeSettings.hiltEnabled}|${runtimeSettings.approvalTimeoutS}`;
    if (cached && key === cachedKey) return cached;
    const host = connection.host.trim().toLowerCase() === "localhost" ? DEFAULT_HOST : connection.host;
    cached = {
      host,
      apiPort: connection.apiPort,
      baseUrl: `http://${host}:${connection.apiPort}`,
      token: readTokenFile(connection.tokenFile),
      guardrailPort: connection.guardrailPort,
      approvalTimeoutS: runtimeSettings.approvalTimeoutS,
      hiltEnabled: runtimeSettings.hiltEnabled,
    };
    cachedKey = key;
    return cached;
  }
  // Resolve outside the permissive config-file fallback below. An invalid
  // explicit data-root override must fail closed instead of silently reading
  // an unrelated account-level installation.
  const defenseClawHome = resolveDefenseClawHome();
  const key = configFilesKey(defenseClawHome);
  if (cached && key === cachedKey) return cached;

  let host = DEFAULT_HOST;
  let apiPort = DEFAULT_API_PORT;
  let guardrailPort = 4000;
  let approvalTimeoutS = 30;
  let hiltEnabled = false;
  let token = "";

  try {
    const cfgPath = join(defenseClawHome, "config.yaml");
    const raw = yaml.load(readFileSync(cfgPath, "utf8")) as Record<string, unknown> | null;
    if (raw && typeof raw === "object") {
      const gw = raw["gateway"] as Record<string, unknown> | undefined;
      if (gw && typeof gw === "object") {
        if (typeof gw["host"] === "string" && gw["host"]) host = gw["host"];
        if (typeof gw["api_port"] === "number") apiPort = gw["api_port"];
        if (typeof gw["approval_timeout_s"] === "number" && gw["approval_timeout_s"] > 0) {
          approvalTimeoutS = gw["approval_timeout_s"];
        }
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

  token = readPluginToken(defenseClawHome);

  // The plugin keys its listener proof by host and connects to it: name the
  // address the gateway binds instead of a name that may resolve to ::1.
  if (host.trim().toLowerCase() === "localhost") host = DEFAULT_HOST;

  cached = {
    host,
    apiPort,
    baseUrl: `http://${host}:${apiPort}`,
    token,
    guardrailPort,
    approvalTimeoutS,
    hiltEnabled,
  };
  cachedKey = key;
  return cached;
}

/** Path, mtime and size of config.yaml and the credential file, to notice when either changes. */
function configFilesKey(defenseClawHome: string): string {
  return ["config.yaml", PLUGIN_TOKEN_FILE]
    .map((name) => {
      const path = join(defenseClawHome, name);
      try {
        const st = statSync(path);
        return `${path}:${st.mtimeMs}:${st.size}`;
      } catch {
        return `${path}:missing`;
      }
    })
    .join("|");
}

/**
 * The plugin credential at <DEFENSECLAW_HOME>/hooks/.hook-openclaw.token, or
 * "" when it is missing or not a 64-character hex token.
 */
function readPluginToken(defenseClawHome: string): string {
  return readTokenFile(join(defenseClawHome, PLUGIN_TOKEN_FILE));
}

/** Clear cached config (for testing). */
export function _resetSidecarConfigCache(): void {
  cached = undefined;
  cachedKey = "";
}

/** Ask the installed gateway binary for the saved OpenClaw outage mode. */
export function loadOpenClawOutageMode(tool?: { name: string; args: Record<string, unknown>; cwd: string }): "open" | "closed" | "protected" {
  try {
    // The account home comes from the OS, not the agent's HOME or
    // DEFENSECLAW_HOME. The helper reads the account's saved config and
    // applies the managed and install-window gates used by hook connectors.
    const accountHome = userInfo().homedir;
    if (!isAbsolute(accountHome)) return "closed";
    const binary = join(accountHome, ".local", "bin",
      process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway");
    const activeHome = resolveDefenseClawHome();
    const hookDir = join(activeHome, "hooks");
    const activeRootEnv = process.env.DEFENSECLAW_HOME
      ? { DEFENSECLAW_HOME: activeHome } : {};
    const env = process.platform === "win32"
      ? { HOME: accountHome, USERPROFILE: accountHome,
          SystemRoot: process.env.SystemRoot || "C:\\Windows",
          PATH: join(process.env.SystemRoot || "C:\\Windows", "System32"), ...activeRootEnv }
      : { HOME: accountHome, PATH: "/usr/bin:/bin", ...activeRootEnv };
    const answer = execFileSync(binary, [
      "hook-outage-mode", "--connector", "openclaw", "--hook-dir", hookDir,
      ...(tool ? ["--tool-payload-stdin"] : []),
    ], {
      encoding: "utf8", timeout: 3000, maxBuffer: 64,
      ...(tool ? { input: JSON.stringify(tool) } : {}),
      env,
      stdio: [tool ? "pipe" : "ignore", "pipe", "ignore"],
    });
    const mode = answer.trim();
    return mode === "open" || mode === "protected" ? mode : "closed";
  } catch {
    return "closed";
  }
}
