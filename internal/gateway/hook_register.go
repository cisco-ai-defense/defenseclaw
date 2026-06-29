// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "net/http"

// init wires the gateway-package hook handlers into the
// connector-name-keyed registry consumed by
// APIServer.registerConnectorHookRoutes. The registry
// removes the case-statement in api.go that previously hard-coded
// per-connector handler dispatch — adding a new connector now needs
// only a registerHookHandler call here, plus a HookEndpoint
// implementation in the connector package.
//
// Every connector — including codex and claudecode — routes through
// handleUnifiedConnectorHook, which delegates to the unified
// handleAgentHook. Connector-specific evaluation, event emission, and
// raw-event correlation live behind the profile-runtime registry while
// all shared concerns stay in one place.
// The unified handler owns:
//
//   - structured audit envelope writes (logConnectorHookAuditEnvelope),
//   - native OTel metrics (RecordHookOutcome / RecordHookTokenUsage),
//   - raw-event deduplication (profile runtime RememberRawEvents),
//   - W3C trace propagation from the agent-side span,
//   - panic recovery across dedupe, emit, evaluate, audit, and
//     metric sections so a single connector bug no longer takes the
//     entire agent estate down.
//
// PR #284 deleted the bespoke handleClaudeCodeHook /
// handleCodexHook handlers. This PR moves the remaining connector
// differences behind HookProfile runtime callbacks so future
// connector changes extend the registry instead of adding another
// gateway hook implementation.
func init() {
	registerHookHandler("claudecode", func(a *APIServer) http.HandlerFunc {
		return a.handleUnifiedConnectorHook("claudecode")
	})
	registerHookHandler("codex", func(a *APIServer) http.HandlerFunc {
		return a.handleUnifiedConnectorHook("codex")
	})
	for _, name := range []string{"hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent"} {
		connectorName := name
		registerHookHandler(connectorName, func(a *APIServer) http.HandlerFunc {
			return a.handleUnifiedConnectorHook(connectorName)
		})
	}
}
