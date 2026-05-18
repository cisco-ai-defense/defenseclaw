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
// APIServer.registerConnectorHookRoutes. Plan C1 / S2.4: this
// removes the case-statement in api.go that previously hard-coded
// per-connector handler dispatch — adding a new connector now needs
// only a registerHookHandler call here, plus a HookEndpoint
// implementation in the connector package.
//
// Every connector — including codex and claudecode — routes through
// handleUnifiedConnectorHook, which delegates to the unified
// handleAgentHook (see bespoke_hook_adapter.go for the dispatch
// shims that route claudecode/codex through their bespoke
// EVALUATORS while keeping all shared concerns in a single place).
// The unified handler owns:
//
//   - structured audit envelope writes (logConnectorHookAuditEnvelope),
//   - native OTel metrics (RecordHookOutcome / RecordHookTokenUsage),
//   - raw-event deduplication (rememberBespokeOrGenericRawEvents),
//   - W3C trace propagation from the agent-side span,
//   - panic recovery (safeEvaluateHook) so a single evaluator bug
//     no longer takes the entire agent estate down.
//
// PR #284 deleted the bespoke handleClaudeCodeHook /
// handleCodexHook handlers; only the bespoke evaluators
// (evaluateClaudeCodeHook / evaluateCodexHook), LLM-event
// emitters, and raw-event dedupers remain — invoked via the
// adapter shims because they read connector-specific request
// fields that the generic agentHookRequest does not model.
func init() {
	registerHookHandler("claudecode", func(a *APIServer) http.HandlerFunc {
		return a.handleUnifiedConnectorHook("claudecode")
	})
	registerHookHandler("codex", func(a *APIServer) http.HandlerFunc {
		return a.handleUnifiedConnectorHook("codex")
	})
	for _, name := range []string{"hermes", "cursor", "windsurf", "geminicli", "copilot"} {
		connectorName := name
		registerHookHandler(connectorName, func(a *APIServer) http.HandlerFunc {
			return a.handleUnifiedConnectorHook(connectorName)
		})
	}
}
