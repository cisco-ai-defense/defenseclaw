// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "testing"

func TestFamilySchemaVersionUsesGeneratedPerFamilyAuthority(t *testing.T) {
	if got, ok := FamilySchemaVersion(TelemetryFamilyApprovalResolve); !ok || got != 2 {
		t.Fatalf("approval family version=%d/%t want=2/true", got, ok)
	}
	for _, family := range []string{TelemetryFamilyTelemetryReceive, TelemetryFamilyTelemetryNormalize} {
		if got, ok := FamilySchemaVersion(family); !ok || got != 1 {
			t.Fatalf("%s family version=%d/%t want=1/true", family, got, ok)
		}
	}
	if got, ok := FamilySchemaVersion("span.unknown"); ok || got != 0 {
		t.Fatalf("unknown family version=%d/%t want=0/false", got, ok)
	}
}
