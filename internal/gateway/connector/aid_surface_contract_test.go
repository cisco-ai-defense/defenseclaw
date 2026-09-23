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
		if entry.NativeHooks.AIDWireVersion != AIDWireVersionChatToolCalls {
			t.Errorf("%s aid_wire_version=%q want %q",
				name, entry.NativeHooks.AIDWireVersion, AIDWireVersionChatToolCalls)
		}
	}
	if checked == 0 {
		t.Fatal("no ungated connector was checked; the manifest shape changed")
	}
}
