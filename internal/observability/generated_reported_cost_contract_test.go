// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"testing"
	"time"
)

func reportedCostTransitionInput() SpanAgentTransitionInput {
	return SpanAgentTransitionInput{
		Envelope: FamilyEnvelopeInput{
			Source: Source("codex"),
			Correlation: Correlation{
				RunID:     "run-cost-contract",
				SessionID: "conversation-cost-contract",
				TraceID:   "0123456789abcdef0123456789abcdef",
				SpanID:    "0123456789abcdef",
				AgentID:   "agent-root",
			},
			Provenance: FamilyProvenanceInput{
				Producer:         "defenseclaw",
				BinaryVersion:    "8.0.0",
				ConfigGeneration: 8,
			},
		},
		Outcome:                           OutcomeAttempted,
		Kind:                              "INTERNAL",
		StartTimeUnixNano:                 1,
		EndTimeUnixNano:                   2,
		Status:                            NewTraceStatusUnset(),
		Resource:                          TraceResourceInput{SchemaURL: "https://opentelemetry.io/schemas/1.42.0"},
		Scope:                             TraceScopeInput{},
		ResourceServiceName:               "defenseclaw",
		ResourceServiceNamespace:          "cisco.ai-defense",
		ResourceServiceInstanceID:         "instance-cost-contract",
		ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID:     "instance-cost-contract",
		GenAIConversationID:               "conversation-cost-contract",
		GenAIAgentID:                      "agent-root",
		DefenseClawAgentRootID:            "agent-root",
		DefenseClawSessionRootID:          "conversation-cost-contract",
		DefenseClawAgentLifecycleID:       "lifecycle-cost-contract",
		DefenseClawAgentExecutionID:       "execution-cost-contract",
		DefenseClawAgentDepth:             0,
		DefenseClawAgentLifecycleEvent:    "turn_start",
		DefenseClawAgentLifecycleState:    "active",
	}
}

func TestGeneratedReportedCostAvailabilityIsFailClosed(t *testing.T) {
	builder, err := NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Unix(1, 0).UTC() }),
		OccurrenceIDGeneratorFunc(func() (string, error) { return "reported-cost-contract", nil }),
	)
	if err != nil {
		t.Fatalf("new family builder: %v", err)
	}

	t.Run("false forbids value", func(t *testing.T) {
		input := reportedCostTransitionInput()
		input.DefenseClawAgentReportedCostPresent = false
		input.DefenseClawAgentReportedCostUsd = Present(0.0)
		_, buildErr := builder.BuildSpanAgentTransition(input)
		if !IsFamilyBuildError(buildErr, FamilyBuildForbiddenField) {
			t.Fatalf("BuildSpanAgentTransition() error = %v, want %s", buildErr, FamilyBuildForbiddenField)
		}
	})

	t.Run("true requires value", func(t *testing.T) {
		input := reportedCostTransitionInput()
		input.DefenseClawAgentReportedCostPresent = true
		input.DefenseClawAgentReportedCostUsd = Absent[float64]()
		_, buildErr := builder.BuildSpanAgentTransition(input)
		if !IsFamilyBuildError(buildErr, FamilyBuildMissingRequired) {
			t.Fatalf("BuildSpanAgentTransition() error = %v, want %s", buildErr, FamilyBuildMissingRequired)
		}
	})
}
