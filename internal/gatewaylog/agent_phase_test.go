// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestNormalizeAgentPhaseRecognizedAliasesAndCasing(t *testing.T) {
	for raw, want := range map[string]string{
		" ToOl ":      AgentPhaseTool,
		"tool_call":   AgentPhaseTool,
		"Plan":        AgentPhasePlanning,
		"permission":  AgentPhaseApproval,
		"IDLE":        AgentPhaseWaiting,
		"response":    AgentPhaseResponding,
		"compaction":  AgentPhaseMaintenance,
		"complete":    AgentPhaseCompleted,
		"failure":     AgentPhaseFailed,
		"cancelled":   AgentPhaseInterrupted,
		"observation": AgentPhaseObserved,
	} {
		got, ok := NormalizeAgentPhase(raw)
		if !ok || got != want {
			t.Errorf("NormalizeAgentPhase(%q)=(%q,%v), want (%q,true)", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "unknown", "toolish", "phase-99"} {
		if got, ok := NormalizeAgentPhase(raw); ok || got != "" {
			t.Errorf("NormalizeAgentPhase(%q)=(%q,%v), want unsupported", raw, got, ok)
		}
	}
}

func TestAgentPhaseContractMatchesRuntimeSchema(t *testing.T) {
	raw, err := os.ReadFile("schemas/gateway-event-envelope.json")
	if err != nil {
		t.Fatalf("read embedded gateway schema: %v", err)
	}
	var schema struct {
		Properties map[string]struct {
			Ref string `json:"$ref"`
		} `json:"properties"`
		Defs map[string]struct {
			Enum []interface{} `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode embedded gateway schema: %v", err)
	}
	const phaseRef = "#/$defs/AgentPhase"
	for _, field := range []string{"agent_phase", "agent_previous_phase"} {
		if got := schema.Properties[field].Ref; got != phaseRef {
			t.Errorf("%s ref=%q want %q", field, got, phaseRef)
		}
	}
	var schemaPhases []string
	for _, value := range schema.Defs["AgentPhase"].Enum {
		if phase, ok := value.(string); ok {
			schemaPhases = append(schemaPhases, phase)
		}
	}
	if want := CanonicalAgentPhases(); !reflect.DeepEqual(schemaPhases, want) {
		t.Fatalf("Go/schema phase drift: go=%v schema=%v", want, schemaPhases)
	}
	for index, phase := range schemaPhases {
		if got, want := AgentPhaseCode(phase), index+1; got != want {
			t.Errorf("AgentPhaseCode(%q)=%d want %d", phase, got, want)
		}
	}
}
