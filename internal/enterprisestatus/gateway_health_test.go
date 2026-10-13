// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"context"
	"testing"
	"time"
)

// GAP-0306, GAP-0409: a lifecycle command reads /health again while the
// gateway's first profile assignment check runs, so its warnings are listed.
func TestSettledGatewayHealthWaitsForTheProfileCheck(t *testing.T) {
	bodies := []string{`{"profile_assignment_check_pending":true}`, `{"profile_assignment_check_pending":true}`,
		`{"profile_assignment_warnings":["assignment 1: group \"S-1-5-21-0-0-0-0\" is not known"]}`}
	calls := 0
	body, err := SettledGatewayHealth(context.Background(), func() ([]byte, error) {
		calls++
		return []byte(bodies[min(calls, len(bodies))-1]), nil
	}, time.Millisecond, 8)
	if err != nil || calls != 3 || ProfileAssignmentCheckPending(body) {
		t.Fatalf("body %s after %d reads (%v), want the settled third", body, calls, err)
	}
	calls = 0
	if _, err := SettledGatewayHealth(context.Background(), func() ([]byte, error) {
		calls++
		return []byte(bodies[0]), nil
	}, time.Millisecond, 2); err != nil || calls != 3 {
		t.Fatalf("a check that never settles is read %d times (%v), want 3", calls, err)
	}
}
