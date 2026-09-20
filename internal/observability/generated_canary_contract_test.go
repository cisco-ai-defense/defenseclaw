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

import "testing"

func TestGeneratedRuntimeCanaryContractIsFailClosed(t *testing.T) {
	contract := generatedSpanModelChatDescriptor{}.familyTraceContract()
	keys := map[string]bool{
		"defenseclaw.telemetry.canary":             true,
		"defenseclaw.telemetry.canary.operation":   true,
		"defenseclaw.telemetry.canary.destination": true,
	}
	fields := make([]familyFieldDescriptor, 0, len(keys))
	for _, field := range contract.fields {
		if keys[field.key] {
			fields = append(fields, field)
		}
	}
	if len(fields) != len(keys) {
		t.Fatalf("canary field inventory = %d, want %d", len(fields), len(keys))
	}
	byKey := make(map[string]familyFieldDescriptor, len(fields))
	for _, field := range fields {
		byKey[field.key] = field
	}
	marker := byKey["defenseclaw.telemetry.canary"]
	operation := byKey["defenseclaw.telemetry.canary.operation"]
	destination := byKey["defenseclaw.telemetry.canary.destination"]
	if marker.requirement != familyRequirementOptional || marker.conditionID != "" ||
		operation.requirement != familyRequirementConditional ||
		operation.conditionID != "telemetry-canary-enabled-v1" ||
		destination.requirement != familyRequirementOptional ||
		destination.conditionID != "telemetry-canary-enabled-v1" ||
		operation.falseRequirement != familyFalseForbidden || destination.falseRequirement != familyFalseForbidden {
		t.Fatalf("generated canary descriptor drift: marker=%+v operation=%+v destination=%+v", marker, operation, destination)
	}

	falseFacts := familyConditionFacts{{id: "telemetry-canary-enabled-v1", state: familyConditionFalse}}
	_, _, err := materializeFamilyFields(
		fields,
		familyFieldValues{{key: destination.key, value: "otlp-primary", present: true}},
		falseFacts,
		familyDerivationContext{},
	)
	if !IsFamilyBuildError(err, FamilyBuildForbiddenField) {
		t.Fatalf("destination without canary marker error = %v", err)
	}

	trueFacts := familyConditionFacts{{id: "telemetry-canary-enabled-v1", state: familyConditionTrue}}
	_, _, err = materializeFamilyFields(
		fields,
		familyFieldValues{{key: marker.key, value: true, present: true}},
		trueFacts,
		familyDerivationContext{},
	)
	if !IsFamilyBuildError(err, FamilyBuildMissingRequired) {
		t.Fatalf("canary without operation error = %v", err)
	}

	attributes, _, err := materializeFamilyFields(
		fields,
		familyFieldValues{
			{key: marker.key, value: true, present: true},
			{key: operation.key, value: "runtime-pipeline-test", present: true},
		},
		trueFacts,
		familyDerivationContext{},
	)
	if err != nil {
		t.Fatalf("canary without optional destination: %v", err)
	}
	if attributes[marker.key] != true || attributes[operation.key] != "runtime-pipeline-test" {
		t.Fatalf("canary attributes = %#v", attributes)
	}
	if _, present := attributes[destination.key]; present {
		t.Fatalf("optional destination was fabricated: %#v", attributes)
	}
}

func TestW3CTraceStateValidation(t *testing.T) {
	for _, value := range []string{"", "vendor=value", "tenant@system=value", "a=1,b=two words"} {
		if !validW3CTraceState(value) {
			t.Fatalf("valid tracestate rejected: %q", value)
		}
	}
	for _, value := range []string{
		"Vendor=value",
		"vendor=value,vendor=duplicate",
		"vendor=value, other=value",
		"vendor=value ",
		"vendor=value=extra",
	} {
		if validW3CTraceState(value) {
			t.Fatalf("invalid tracestate accepted: %q", value)
		}
	}
}
