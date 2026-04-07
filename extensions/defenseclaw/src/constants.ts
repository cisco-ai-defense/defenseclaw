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
 * Centralized constants for the DefenseClaw OpenClaw plugin.
 *
 * All hardcoded values (ports, timeouts, header names, limits, paths, env vars)
 * live here so they can be imported from a single source of truth.
 */

// --- Network defaults ---
export const DEFAULT_SIDECAR_HOST = "127.0.0.1";
export const DEFAULT_SIDECAR_API_PORT = 18970;
export const DEFAULT_GUARDRAIL_PORT = 4000;
export const LOOPBACK_ADDRESS = "127.0.0.1";

// --- Header names ---
export const HEADER_TARGET_URL = "X-DC-Target-URL";
export const HEADER_AI_AUTH = "X-AI-Auth";
export const HEADER_DC_AUTH = "X-DC-Auth";

// --- Timeouts (ms) ---
export const INSPECT_TIMEOUT_MS = 2_000;
export const REQUEST_TIMEOUT_MS = 30_000;
export const SKILL_SCAN_TIMEOUT_MS = 120_000;
export const CODE_SCAN_TIMEOUT_MS = 30_000;

// --- Limits ---
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
export const MAX_EXEC_BUFFER = 10 * 1024 * 1024;

// --- API paths ---
export const INSPECT_TOOL_PATH = "/api/v1/inspect/tool";

// --- Environment variables ---
export const TOKEN_ENV_VAR = "OPENCLAW_GATEWAY_TOKEN";
