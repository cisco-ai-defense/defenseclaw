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
	"strings"
	"testing"
	"time"
)

func TestGeneratedCustomResourceAttributesAreSealedAndCopied(t *testing.T) {
	input := map[string]string{"operator.profile": "soc"}
	attributes, err := NewTelemetryCustomResourceAttributes(input, true)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	input["operator.profile"] = "mutated"
	first := attributes.Values()
	if first["operator.profile"] != "soc" || !attributes.CompatibilityAliasesEnabled() {
		t.Fatalf("sealed attributes = %#v, aliases=%v", first, attributes.CompatibilityAliasesEnabled())
	}
	first["operator.profile"] = "mutated again"
	if attributes.Values()["operator.profile"] != "soc" {
		t.Fatal("Values returned mutable backing state")
	}

	var zero TelemetryCustomResourceAttributes
	if len(zero.Values()) != 0 || zero.CompatibilityAliasesEnabled() {
		t.Fatalf("zero value = %#v, aliases=%v", zero.Values(), zero.CompatibilityAliasesEnabled())
	}
}

func TestGeneratedCustomResourceAttributesRejectUnsafeAndCollidingInputs(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
		code   FamilyBuildErrorCode
	}{
		{name: "fixed", values: map[string]string{"service.name": "other"}, code: FamilyBuildForbiddenField},
		{name: "alias", values: map[string]string{"deployment.mode": "edge"}, code: FamilyBuildForbiddenField},
		{name: "process owned", values: map[string]string{"discovery.source": "runtime"}, code: FamilyBuildForbiddenField},
		{name: "normalized fixed", values: map[string]string{"service-name": "other"}, code: FamilyBuildForbiddenField},
		{name: "secret segment", values: map[string]string{"operator.token.kind": "opaque"}, code: FamilyBuildConstraint},
		{name: "path segment", values: map[string]string{"operator.file.kind": "opaque"}, code: FamilyBuildConstraint},
		{name: "path value", values: map[string]string{"operator.profile": "/private/location"}, code: FamilyBuildForbiddenField},
		{name: "whitespace path value", values: map[string]string{"operator.profile": "  /private/location  "}, code: FamilyBuildForbiddenField},
		{name: "whitespace bearer value", values: map[string]string{"operator.profile": "  Bearer opaque  "}, code: FamilyBuildForbiddenField},
		{name: "unicode whitespace basic value", values: map[string]string{"operator.profile": "\u2003Basic opaque\u2003"}, code: FamilyBuildForbiddenField},
		{name: "normalized pair", values: map[string]string{
			"operator.profile-name": "one", "operator.profile.name": "two",
		}, code: FamilyBuildDuplicateField},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewTelemetryCustomResourceAttributes(test.values, false)
			if !IsFamilyBuildError(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
			for key, value := range test.values {
				if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), value) {
					t.Fatalf("error exposed custom resource content: %q", err)
				}
			}
		})
	}
}

func TestGeneratedCustomResourceAttributesEnforceBounds(t *testing.T) {
	atLimit := make(map[string]string, 64)
	for index := 0; index < 64; index++ {
		atLimit["operator.profile"+string(rune('A'+index%26))+string(rune('a'+index/26))] = "x"
	}
	if _, err := NewTelemetryCustomResourceAttributes(atLimit, false); err != nil {
		t.Fatalf("64 attributes: %v", err)
	}
	atLimit["operator.overflow"] = "x"
	if _, err := NewTelemetryCustomResourceAttributes(atLimit, false); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("65 attributes error = %v", err)
	}
	if _, err := NewTelemetryCustomResourceAttributes(
		map[string]string{"operator.profile": strings.Repeat("x", 1024)}, false,
	); err != nil {
		t.Fatalf("1024-byte value: %v", err)
	}
	if _, err := NewTelemetryCustomResourceAttributes(
		map[string]string{"operator.profile": strings.Repeat("x", 1025)}, false,
	); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("1025-byte value error = %v", err)
	}
}

func TestGeneratedCustomResourceValidationErrorsAreDeterministic(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		values := make(map[string]string, 2)
		if iteration%2 == 0 {
			values["z.profile"] = "/private/location"
			values["a.secret"] = "opaque"
		} else {
			values["a.secret"] = "opaque"
			values["z.profile"] = "/private/location"
		}
		_, err := NewTelemetryCustomResourceAttributes(values, false)
		if !IsFamilyBuildError(err, FamilyBuildConstraint) {
			t.Fatalf("iteration %d constructor error = %v, want %s", iteration, err, FamilyBuildConstraint)
		}

		complete := map[string]any{
			"a.custom":                    7,
			"deployment.environment.name": "test",
			"defenseclaw.instance.id":     "instance",
			"service.instance.id":         "service-instance",
			"service.name":                "defenseclaw",
			"service.namespace":           "defenseclaw",
			"service.version":             "test",
			"z.profile":                   "/private/location",
		}
		err = ValidateTelemetryResourceAttributes(complete)
		if !IsFamilyBuildError(err, FamilyBuildInvalidType) {
			t.Fatalf("iteration %d complete-map error = %v, want %s", iteration, err, FamilyBuildInvalidType)
		}
	}
}

func TestGeneratedCustomResourceAttributesAndAliasesReachCanonicalRecord(t *testing.T) {
	custom, err := NewTelemetryCustomResourceAttributes(map[string]string{"operator.profile": "soc"}, true)
	if err != nil {
		t.Fatalf("custom resource: %v", err)
	}
	input := reportedCostTransitionInput()
	input.Resource = WithTelemetryCustomResourceAttributes(input.Resource, custom)
	input.ResourceDefenseClawDeploymentMode = Present("edge")
	input.ResourceDefenseClawDevicePublicKeyFingerprint = Present("sha256:device")
	builder, err := NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Unix(1, 0).UTC() }),
		OccurrenceIDGeneratorFunc(func() (string, error) { return "custom-resource-contract", nil }),
	)
	if err != nil {
		t.Fatalf("builder: %v", err)
	}
	record, err := builder.BuildSpanAgentTransition(input)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body, present := record.Body()
	if !present {
		t.Fatal("trace body absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatalf("trace body object: %v", err)
	}
	resource := object["resource"].(map[string]any)
	values := resource["attributes"].(map[string]any)
	want := map[string]string{
		"operator.profile":       "soc",
		"deployment.environment": "test",
		"deployment.mode":        "edge",
		"defenseclaw.device.id":  "sha256:device",
	}
	for key, value := range want {
		if values[key] != value {
			t.Fatalf("resource[%s] = %#v, want %q", key, values[key], value)
		}
	}
	if err := ValidateTelemetryResourceAttributes(values); err != nil {
		t.Fatalf("complete resource validation: %v", err)
	}
	classes := record.FieldClasses()
	if classes["/resource/attributes/operator.profile"] != FieldClassMetadata ||
		classes["/resource/attributes/defenseclaw.device.id"] != FieldClassIdentifier {
		t.Fatalf("resource classes = %#v", classes)
	}
}

func TestGeneratedCompleteResourceValidationRejectsForgedMaps(t *testing.T) {
	custom, err := NewTelemetryCustomResourceAttributes(map[string]string{"operator.profile": "soc"}, true)
	if err != nil {
		t.Fatalf("custom resource: %v", err)
	}
	input := reportedCostTransitionInput()
	input.Resource = WithTelemetryCustomResourceAttributes(input.Resource, custom)
	input.ResourceDefenseClawDeploymentMode = Present("edge")
	builder, err := NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Unix(1, 0).UTC() }),
		OccurrenceIDGeneratorFunc(func() (string, error) { return "resource-validation", nil }),
	)
	if err != nil {
		t.Fatalf("builder: %v", err)
	}
	record, err := builder.BuildSpanAgentTransition(input)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body, _ := record.Body()
	object, _ := body.Object()
	base := object["resource"].(map[string]any)["attributes"].(map[string]any)

	clone := func() map[string]any {
		result := make(map[string]any, len(base))
		for key, value := range base {
			result[key] = value
		}
		return result
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		code   FamilyBuildErrorCode
	}{
		{name: "secret custom field", mutate: func(values map[string]any) {
			values["resource.secret"] = "opaque"
		}, code: FamilyBuildConstraint},
		{name: "non string custom field", mutate: func(values map[string]any) {
			values["operator.level"] = 7
		}, code: FamilyBuildInvalidType},
		{name: "non string fixed field", mutate: func(values map[string]any) {
			values["service.name"] = 7
		}, code: FamilyBuildInvalidType},
		{name: "missing required fixed field", mutate: func(values map[string]any) {
			delete(values, "service.name")
		}, code: FamilyBuildMissingRequired},
		{name: "alias differs from canonical", mutate: func(values map[string]any) {
			values["deployment.mode"] = "other"
		}, code: FamilyBuildConstraint},
		{name: "normalized custom collision", mutate: func(values map[string]any) {
			values["operator.profile-name"] = "one"
			values["operator.profile.name"] = "two"
		}, code: FamilyBuildDuplicateField},
		{name: "sixty five custom members", mutate: func(values map[string]any) {
			for index := 0; index < 64; index++ {
				values["operator.extra"+string(rune('A'+index%26))+string(rune('a'+index/26))] = "x"
			}
		}, code: FamilyBuildConstraint},
		{name: "custom aggregate above sixteen kibibytes", mutate: func(values map[string]any) {
			for index := 0; index < 17; index++ {
				values["operator.aggregate"+string(rune('A'+index))] = strings.Repeat("x", 1000)
			}
		}, code: FamilyBuildConstraint},
		{name: "custom utf8 byte overflow", mutate: func(values map[string]any) {
			values["operator.utf8"] = strings.Repeat("é", 513)
		}, code: FamilyBuildConstraint},
		{name: "normalized custom fixed collision", mutate: func(values map[string]any) {
			values["service-name"] = "other"
		}, code: FamilyBuildForbiddenField},
		{name: "whitespace prefixed path", mutate: func(values map[string]any) {
			values["operator.location"] = "  /private/location  "
		}, code: FamilyBuildForbiddenField},
		{name: "whitespace prefixed bearer credential", mutate: func(values map[string]any) {
			values["operator.profile"] = "\u2003Bearer opaque\u2003"
		}, code: FamilyBuildForbiddenField},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := clone()
			test.mutate(values)
			err := ValidateTelemetryResourceAttributes(values)
			if !IsFamilyBuildError(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
			if strings.Contains(err.Error(), "resource.secret") || strings.Contains(err.Error(), "opaque") {
				t.Fatalf("error exposed forged content: %q", err)
			}
		})
	}
}
