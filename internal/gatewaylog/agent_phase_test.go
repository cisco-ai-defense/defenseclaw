// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"encoding/json"
	"reflect"
	"strings"
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
	raw, err := embeddedSchemas.ReadFile("schemas/gateway-event-envelope.json")
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

func TestWriterNormalizesOptionalPreviousPhaseBeforeStrictSchemaGate(t *testing.T) {
	validator, err := NewDefaultValidator()
	if err != nil {
		t.Fatalf("NewDefaultValidator: %v", err)
	}
	writer, err := New(Config{Validator: validator})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var events []Event
	writer.WithFanout(func(event Event) { events = append(events, event) })

	base := Event{
		EventType:     EventLifecycle,
		AgentPhase:    " ToOl ",
		AgentSequence: 1,
		Lifecycle:     &LifecyclePayload{Subsystem: "agent", Transition: "start"},
	}
	unsupported := base
	unsupported.AgentPreviousPhase = "unknown"
	writer.Emit(unsupported)
	alias := base
	alias.AgentPreviousPhase = "Plan"
	writer.Emit(alias)

	if got := writer.SchemaViolationsCount(); got != 0 {
		t.Fatalf("schema violations=%d want 0", got)
	}
	if len(events) != 2 {
		t.Fatalf("fanout events=%d want 2: %+v", len(events), events)
	}
	if events[0].AgentPhase != AgentPhaseTool || events[0].AgentPreviousPhase != "" {
		t.Errorf("unsupported previous phase not omitted: %+v", events[0])
	}
	if events[1].AgentPhase != AgentPhaseTool || events[1].AgentPreviousPhase != AgentPhasePlanning {
		t.Errorf("recognized alias not canonicalized: %+v", events[1])
	}
}

func TestRuntimeSchemaStillRejectsMalformedPhaseAndUnrelatedFields(t *testing.T) {
	validator := newRepoValidator(t)
	valid := Event{
		SchemaVersion:      7,
		EventType:          EventLifecycle,
		Severity:           SeverityInfo,
		AgentPhase:         AgentPhaseTool,
		AgentPreviousPhase: AgentPhasePlanning,
		AgentSequence:      1,
		Lifecycle:          &LifecyclePayload{Subsystem: "agent", Transition: "start"},
	}
	if err := validator.Validate(valid); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	invalidPrevious := valid
	invalidPrevious.AgentPreviousPhase = "unknown"
	if err := validator.Validate(invalidPrevious); err == nil {
		t.Fatal("raw schema accepted unsupported agent_previous_phase")
	} else if got := err.Error(); !strings.Contains(got, "/agent_previous_phase") {
		t.Fatalf("previous-phase violation lost exact path for value %q: %v", invalidPrevious.AgentPreviousPhase, err)
	}
	invalidCurrent := valid
	invalidCurrent.AgentPhase = "toolish"
	if err := validator.Validate(invalidCurrent); err == nil {
		t.Fatal("raw schema accepted unsupported agent_phase")
	}
	invalidPayload := valid
	invalidPayload.Lifecycle = &LifecyclePayload{Subsystem: "agent", Transition: "not-a-transition"}
	if err := validator.Validate(invalidPayload); err == nil {
		t.Fatal("schema accepted unrelated malformed lifecycle field")
	}
	for _, schemaVersion := range []int{7, 8} {
		compatible := valid
		compatible.SchemaVersion = schemaVersion
		if err := validator.Validate(compatible); err != nil {
			t.Errorf("schema_version=%d rejected: %v", schemaVersion, err)
		}
	}
}
