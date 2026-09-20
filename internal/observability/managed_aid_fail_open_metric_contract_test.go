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

func TestManagedAIDFailOpenMetricReasonContract(t *testing.T) {
	for _, reason := range []string{
		"inspector_unwired",
		"aid_unavailable",
		"no_content",
		"unknown",
	} {
		t.Run("accepts_"+reason, func(t *testing.T) {
			builder, _ := testFamilyBuilder(t)
			record, err := builder.BuildMetricDefenseClawManagedAidFailOpenDecisions(
				MetricDefenseClawManagedAidFailOpenDecisionsInput{
					Envelope:                testFamilyEnvelope(),
					Value:                   1,
					DefenseClawMetricReason: reason,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			instrumentValue, present := record.InstrumentData()
			if !present {
				t.Fatal("managed AID fail-open metric has no instrument data")
			}
			instrument, err := instrumentValue.Object()
			if err != nil {
				t.Fatal(err)
			}
			attributes, ok := instrument["attributes"].(map[string]any)
			if !ok || attributes["defenseclaw.metric.reason"] != reason {
				t.Fatalf("managed AID fail-open attributes = %#v", instrument["attributes"])
			}
		})
	}

	for _, reason := range []string{"", "future_unbounded_reason"} {
		t.Run("rejects_"+reason, func(t *testing.T) {
			builder, _ := testFamilyBuilder(t)
			_, err := builder.BuildMetricDefenseClawManagedAidFailOpenDecisions(
				MetricDefenseClawManagedAidFailOpenDecisionsInput{
					Envelope:                testFamilyEnvelope(),
					Value:                   1,
					DefenseClawMetricReason: reason,
				},
			)
			if !IsFamilyBuildError(err, FamilyBuildConstraint) {
				t.Fatalf("reason %q error = %v, want %s", reason, err, FamilyBuildConstraint)
			}
		})
	}
}
