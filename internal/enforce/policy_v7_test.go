// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"testing"
)

func TestPolicyStableID_Deterministic(t *testing.T) {
	a := PolicyStableID("/tmp/policies")
	b := PolicyStableID("/tmp/policies")
	if a != b || a == "" || a == "none" {
		t.Fatalf("PolicyStableID=%q a=%q b=%q", a, a, b)
	}
	if PolicyStableID("") != "none" {
		t.Fatal("empty dir should be none")
	}
}

func TestAdmissionDecideSpan_EndToEnd(t *testing.T) {
	ctx := context.Background()
	_, span := StartAdmissionDecideSpan(ctx, "skill", "my-skill", "pol-1")
	if span == nil {
		t.Fatal("expected span")
	}
	EndAdmissionDecideSpan(span, "blocked", "unit test", "pol-1", nil)

	// Accept nil span (OTel disabled / noop):
	EndAdmissionDecideSpan(nil, "clean", "", "", nil)
}
