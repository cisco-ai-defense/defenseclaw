// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Connectors with no versioned contract still reach Cisco AI Defense, so the
// manifest declares their events and encoding under native_hook_inventory.
// Without this the registry would describe only the version-gated connectors.
func TestManifestUngatedConnectorsDeclareAIDSurfaces(t *testing.T) {
	type inventory struct {
		Events           []string            `json:"events"`
		BlockEvents      []string            `json:"block_events"`
		AIDSurfaces      []string            `json:"aid_surfaces"`
		AIDSurfaceEvents map[string][]string `json:"aid_surface_events"`
		AIDWireVersion   string              `json:"aid_wire_version"`
	}
	type connectorEntry struct {
		Kind              string     `json:"kind"`
		CompatibilityGate string     `json:"compatibility_gate"`
		Contracts         []struct{} `json:"contracts"`
		NativeHooks       *inventory `json:"native_hook_inventory"`
	}
	var manifest struct {
		Connectors map[string]connectorEntry `json:"connectors"`
	}

	path := filepath.Join("..", "..", "..", "cli", "defenseclaw", "inventory", "hook_contracts.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hook contract manifest: %v", err)
	}
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("unmarshal hook contract manifest: %v", err)
	}

	checked := 0
	for name, entry := range manifest.Connectors {
		if len(entry.Contracts) > 0 || entry.Kind == "proxy" {
			continue
		}
		if entry.NativeHooks == nil {
			t.Errorf("%s has no versioned contract and no native_hook_inventory", name)
			continue
		}
		checked++
		declared := make(map[string]bool, len(entry.NativeHooks.Events))
		for _, event := range entry.NativeHooks.Events {
			declared[canonicalHookEvent(event)] = true
		}
		for surface, events := range entry.NativeHooks.AIDSurfaceEvents {
			for _, event := range events {
				if !declared[canonicalHookEvent(event)] {
					t.Errorf("%s aid_surface_events[%q] names %q, which is not in events",
						name, surface, event)
				}
			}
		}
		for _, surface := range entry.NativeHooks.AIDSurfaces {
			if len(entry.NativeHooks.AIDSurfaceEvents[surface]) == 0 && surface != AIDSurfaceEventContent {
				t.Errorf("%s declares aid surface %q with no events", name, surface)
			}
		}
		checkAIDSurfaceClassification(t, name, entry.NativeHooks.Events,
			entry.NativeHooks.AIDSurfaces, entry.NativeHooks.AIDSurfaceEvents)
		if entry.NativeHooks.AIDWireVersion != AIDWireVersionChatToolCalls {
			t.Errorf("%s aid_wire_version=%q want %q",
				name, entry.NativeHooks.AIDWireVersion, AIDWireVersionChatToolCalls)
		}
	}
	if checked == 0 {
		t.Fatal("no ungated connector was checked; the manifest shape changed")
	}
}

// Sandbox-only contracts are built outside builtinHookContracts, so the init
// that fills in their AID declaration never sees them. Each one that reaches
// AID still names its events and its encoding.
func TestSandboxOnlyContractsDeclareAIDSurfaces(t *testing.T) {
	checked := 0
	for name := range sandboxOnlyHookContractsByConnector {
		for _, contract := range sandboxOnlyHookContracts(name) {
			if len(contract.AIDSurfaces) == 0 {
				continue
			}
			checked++
			if contract.AIDWireVersion != AIDWireVersionChatToolCalls {
				t.Errorf("%s aid_wire_version=%q want %q",
					contract.ContractID, contract.AIDWireVersion, AIDWireVersionChatToolCalls)
			}
			events := make(map[string]bool, len(contract.Events))
			for _, event := range contract.Events {
				events[canonicalHookEvent(event)] = true
			}
			for _, surface := range contract.AIDSurfaces {
				if surface == AIDSurfaceEventContent {
					continue
				}
				declared := contract.AIDSurfaceEvents[surface]
				if len(declared) == 0 {
					t.Errorf("%s declares aid surface %q with no events", contract.ContractID, surface)
				}
				for _, event := range declared {
					if !events[canonicalHookEvent(event)] {
						t.Errorf("%s aid_surface_events[%q] names %q, which is not in events",
							contract.ContractID, surface, event)
					}
				}
			}
			checkAIDSurfaceClassification(t, contract.ContractID, contract.Events,
				contract.AIDSurfaces, contract.AIDSurfaceEvents)
			if routed := intersectEvents(contract.Routing().StructuredActionEvents, contract.Events); len(routed) > 0 &&
				!sameStrings(contract.AIDSurfaceEvents[AIDSurfaceToolCall], routed) {
				t.Errorf("%s aid_surface_events[tool_call]=%v, want the routed %v",
					contract.ContractID, contract.AIDSurfaceEvents[AIDSurfaceToolCall], routed)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no sandbox-only contract reaching AID was checked")
	}
}

// checkAIDSurfaceClassification holds a hand-written declaration to the
// runtime classification the derived ones come from: prompt and tool_result
// list exactly the events the canonical spellings select, and a tool_call
// event is neither a prompt nor a result.
func checkAIDSurfaceClassification(
	t *testing.T,
	label string,
	events, surfaces []string,
	declared map[string][]string,
) {
	t.Helper()
	carried := make(map[string]bool, len(surfaces))
	for _, surface := range surfaces {
		carried[surface] = true
	}
	for surface, canonical := range map[string]map[string]bool{
		AIDSurfacePrompt:     aidPromptSurfaceEvents,
		AIDSurfaceToolResult: aidToolResultSurfaceEvents,
	} {
		if !carried[surface] {
			continue
		}
		if want := filterEvents(events, canonical); !sameStrings(declared[surface], want) {
			t.Errorf("%s aid_surface_events[%q]=%v, want %v", label, surface, declared[surface], want)
		}
	}
	for _, event := range declared[AIDSurfaceToolCall] {
		key := canonicalHookEvent(event)
		if aidPromptSurfaceEvents[key] || aidToolResultSurfaceEvents[key] {
			t.Errorf("%s aid_surface_events[tool_call] names %q, a prompt or result event", label, event)
		}
	}
}
