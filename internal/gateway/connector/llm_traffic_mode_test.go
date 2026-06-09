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

package connector

import "testing"

// TestLLMTrafficModeForConnector pins the per-connector traffic mode
// that drives the honest custom-provider UX: only the two proxy
// connectors enforce a custom provider on the agent's own model
// traffic; every hook connector applies it to the judge/aux model only.
func TestLLMTrafficModeForConnector(t *testing.T) {
	proxy := []string{"openclaw", "zeptoclaw"}
	hooks := []string{
		"claudecode", "codex", "hermes", "cursor", "windsurf",
		"geminicli", "copilot", "openhands", "antigravity", "opencode",
	}
	for _, name := range proxy {
		if got := LLMTrafficModeForConnector(name); got != LLMTrafficModeProxy {
			t.Errorf("LLMTrafficModeForConnector(%q)=%q, want %q", name, got, LLMTrafficModeProxy)
		}
	}
	for _, name := range hooks {
		if got := LLMTrafficModeForConnector(name); got != LLMTrafficModeHooksOnly {
			t.Errorf("LLMTrafficModeForConnector(%q)=%q, want %q", name, got, LLMTrafficModeHooksOnly)
		}
	}
	// Alias normalization (e.g. "claude-code") still resolves correctly.
	if got := LLMTrafficModeForConnector("claude-code"); got != LLMTrafficModeHooksOnly {
		t.Errorf("alias claude-code mode=%q, want hooks-only", got)
	}
	// Unknown connectors default to hooks-only (the safe, non-enforcing
	// assumption — never claim a custom provider is enforced when we
	// can't prove a proxy data path).
	if got := LLMTrafficModeForConnector("made-up"); got != LLMTrafficModeHooksOnly {
		t.Errorf("unknown connector mode=%q, want hooks-only", got)
	}
}

// TestHookOnlyConnectorCapabilities_SetLLMTrafficMode asserts the
// capability matrix every hook connector emits carries the hooks-only
// traffic mode, so /v1/connectors and the CLI render the judge-only
// custom-provider wording.
func TestHookOnlyConnectorCapabilities_SetLLMTrafficMode(t *testing.T) {
	for _, c := range []*hookOnlyConnector{
		NewHermesConnector(), NewOpenCodeConnector(), NewCursorConnector(),
	} {
		caps := c.Capabilities(SetupOpts{APIAddr: "127.0.0.1:18970"})
		if caps.LLMTrafficMode != LLMTrafficModeHooksOnly {
			t.Errorf("%s Capabilities.LLMTrafficMode=%q, want hooks-only", c.Name(), caps.LLMTrafficMode)
		}
	}
}
