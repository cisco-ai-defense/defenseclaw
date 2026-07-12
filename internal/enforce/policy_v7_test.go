// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enforce

import (
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
