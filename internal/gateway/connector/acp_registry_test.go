// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestACPRegistryCoversEveryBuiltinConnector(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "inventory", "acp_registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Agents []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"agents"`
		Coverage []struct {
			ConnectorID string `json:"connector_id"`
			Support     string `json:"acp_support"`
			AgentID     string `json:"agent_id"`
		} `json:"connector_coverage"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	want := NewDefaultRegistry().Names()
	agents := make(map[string]string, len(document.Agents))
	for _, agent := range document.Agents {
		if _, exists := agents[agent.ID]; exists {
			t.Fatalf("duplicate ACP agent %q", agent.ID)
		}
		agents[agent.ID] = agent.Kind
	}
	got := make([]string, 0, len(document.Coverage))
	seen := map[string]bool{}
	for _, row := range document.Coverage {
		if seen[row.ConnectorID] {
			t.Fatalf("duplicate ACP coverage row for %q", row.ConnectorID)
		}
		seen[row.ConnectorID] = true
		got = append(got, row.ConnectorID)
		if row.Support == "none" && row.AgentID != "" {
			t.Fatalf("non-ACP connector %q has agent_id %q", row.ConnectorID, row.AgentID)
		}
		if row.Support != "none" && row.AgentID == "" {
			t.Fatalf("ACP connector %q is missing agent_id", row.ConnectorID)
		}
		if row.Support != "none" && agents[row.AgentID] != row.Support {
			t.Fatalf("ACP connector %q support %q differs from agent %q kind %q", row.ConnectorID, row.Support, row.AgentID, agents[row.AgentID])
		}
		if row.Support == "native" {
			capability := ACPAgentCapabilityForConnector(row.ConnectorID)
			if !capability.Agent || capability.Kind != "native" {
				t.Fatalf("native ACP connector %q does not publish agent capability", row.ConnectorID)
			}
		} else if row.Support == "bridge" {
			capability := ACPAgentCapabilityForConnector(row.ConnectorID)
			if !capability.Agent || capability.Kind != "bridge" {
				t.Fatalf("bridge ACP connector %q does not publish bridge capability", row.ConnectorID)
			}
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ACP coverage connectors = %v, want all builtins %v", got, want)
	}
}
