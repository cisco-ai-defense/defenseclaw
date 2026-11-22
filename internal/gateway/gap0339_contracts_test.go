// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// Every connector the kit builds an actor for has a sandbox hook contract
// whose tool-call lifecycle feeds the tool chains: it routes a pre-tool
// event as a structured action, validates against the contract's events,
// and the contract's hook events get a correlation (not one bound to ACP
// only). A new connector, or a contract without a lifecycle, fails here
// instead of leaving an actor's reads out of the secret-read chain
// (substrate-1 GAP-0337, GAP-0338, GAP-0339).
func TestEverySubstrateConnectorFeedsTheToolChains(t *testing.T) {
	if len(kit.Connectors()) == 0 {
		t.Fatal("the kit lists no connector")
	}
	for _, name := range kit.Connectors() {
		t.Run(name, func(t *testing.T) {
			version := kit.AgentVersion(name, "")
			resolution := connector.ResolveSandboxHookContract(name, version)
			contract := resolution.Contract
			if contract.ContractID == "" {
				t.Fatalf("no sandbox hook contract for %s %s: %s %s", name, version, resolution.Status, resolution.Reason)
			}
			lifecycle := contract.ToolCallLifecycle
			if err := connector.ValidateToolCallLifecycleContract(lifecycle, contract.Events); err != nil {
				t.Fatalf("%s: the tool-call lifecycle does not feed the chains: %v", contract.ContractID, err)
			}
			structured := false
			for _, event := range lifecycle.PreProposalEvents {
				if lifecycle.RouteForEvent(event) == connector.ToolEventRouteStructuredAction {
					structured = true
				}
			}
			if !structured {
				t.Fatalf("%s: no pre-tool event is routed as a structured action: %+v", contract.ContractID, lifecycle.Routing)
			}
			if spec, ok := connector.CorrelationSpecForConnector(name, contract.ContractID); ok && len(spec.HookBindings) == 0 {
				t.Fatalf("%s: the correlation profile %s binds no hook field (surfaces %v), so hook events keep no chain state",
					contract.ContractID, spec.ProfileVersion, spec.Surfaces)
			}
			// Every event that can carry a tool call is routed: an unrouted
			// one is reported unrecorded on every call (GAP-0339 review F5).
			for _, event := range contract.Events {
				if toolCarryingEvent(contract, event) && lifecycle.RouteForEvent(event) == connector.ToolEventRouteUnknown {
					t.Errorf("%s: event %q can carry a tool call but the lifecycle routes it nowhere", contract.ContractID, event)
				}
			}
			// The gateway's own resolution of an actor's binding makes the
			// lifecycle active (a sandbox binding pins the contract).
			provider, ok := (&APIServer{}).hookProfileProvider(name)
			if !ok {
				t.Fatalf("%s: no hook profile provider", name)
			}
			profile := provider.HookProfile(connector.SetupOpts{AgentVersion: version, HookContractID: contract.ContractID, GOOS: sandboxauth.SandboxGOOS})
			if profile.ContractID != contract.ContractID || !profile.ExperimentalToolLifecycleEligible() {
				t.Fatalf("%s: the gateway resolves contract %q (%s: %s), lifecycle active=%v",
					contract.ContractID, profile.ContractID, profile.CompatibilityStatus, profile.CompatibilityReason, profile.ExperimentalToolLifecycleEligible())
			}
		})
	}
}

// toolCarryingEvent reports a contract event whose payload carries a tool
// call or its result: the contract's tool-result AID events, or an event
// named for a tool, a command, an approval or a permission. The tool-call
// AID events also list model replies (they may hold tool calls), which carry
// no tool name of their own.
func toolCarryingEvent(contract connector.HookContract, event string) bool {
	for _, surface := range []string{connector.AIDSurfaceToolResult} {
		for _, e := range contract.AIDSurfaceEvents[surface] {
			if e == event {
				return true
			}
		}
	}
	lower := strings.ToLower(event)
	for _, word := range []string{"tool", "shell", "command", "terminal", "approval", "permission", "mcp"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}
