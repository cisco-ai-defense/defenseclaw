// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Vault auto-capture reads every harness that runs in a sandbox, and each
// event it places is one the harness's pinned hook contract registers in
// the lifecycle route it is placed in: a tool call is a structured action
// the harness can block, a tool output a result (or result-rewriting) event.
func TestVaultCaptureCoversEverySandboxHarness(t *testing.T) {
	names := Names()
	covered := connector.SandboxVaultCaptureConnectors()
	sort.Strings(names)
	sort.Strings(covered)
	if !slices.Equal(names, covered) {
		t.Fatalf("vault capture reads %v; sandbox harnesses are %v", covered, names)
	}
	// Events a newer or older pin than the default registers.
	versioned := map[string]bool{"copilot/userPromptTransformed": true}
	// A subagent launch the harness can deny that is not routed as a
	// structured tool action: its task is model-written, so capture places
	// it as a tool call, and it must still be blockable.
	delegation := map[string]bool{"cursor/subagentStart": true}
	for _, name := range names {
		spec, _ := Get(name)
		provider, ok := spec.Provider.(connector.HookProfileProvider)
		if !ok {
			t.Fatalf("%s: no hook profile", name)
		}
		contract := connector.ResolveSandboxHookContract(name, spec.DefaultVersion)
		profile := provider.HookProfile(connector.SetupOpts{
			DataDir: t.TempDir(), APIAddr: "127.0.0.1:1", GOOS: "linux",
			AgentVersion: spec.DefaultVersion, HookContractID: contract.Contract.ContractID,
		})
		in := func(event string, list []string) bool {
			return slices.ContainsFunc(list, func(e string) bool { return strings.EqualFold(e, event) })
		}
		routing := profile.ToolCallLifecycle.Routing
		for event, ce := range connector.SandboxVaultCaptureEvents(name) {
			if !in(event, profile.SupportedEvents) {
				if !versioned[name+"/"+event] {
					t.Errorf("%s: capture places %s, which the pinned contract does not register", name, event)
				}
				continue
			}
			switch ce.Point {
			case connector.VaultCaptureToolCall:
				structured := in(event, routing.StructuredActionEvents) || delegation[name+"/"+event]
				if !structured || !in(event, profile.Capabilities.BlockEvents) {
					t.Errorf("%s: tool call event %s is not a blockable structured action", name, event)
				}
			case connector.VaultCaptureToolOutput:
				// Hermes's transform_* hooks rewrite a result and are routed
				// audit-only.
				if !in(event, routing.ResultContentEvents) && !in(event, routing.AuditOnlyEvents) {
					t.Errorf("%s: tool output event %s is not a result event", name, event)
				}
				if ce.Stop && !in(event, profile.Capabilities.BlockEvents) {
					t.Errorf("%s: %s is answered block but cannot block", name, event)
				}
			case connector.VaultCapturePrompt:
				if !in(event, profile.Capabilities.BlockEvents) {
					t.Errorf("%s: prompt event %s is marked stoppable but cannot block", name, event)
				}
			}
		}
	}
}
