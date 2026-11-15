// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10:GAP-0800: while the managed Windows route epoch is not
// published, /health route-only is not ready and says why; the guardian
// cannot render any account then.
func TestRouteOnlyReadinessWaitsForAPublishedRouteEpoch(t *testing.T) {
	failing := errors.New("open C:\\data\\hooks\\.route-epoch-1: Access is denied.")
	s := &routeEpochState{dataDir: func() string { return t.TempDir() }, seen: map[string]bool{},
		write: func(string, connector.RouteEpoch) error { return failing }}
	if got := s.unpublished(); !strings.Contains(got, "not started") {
		t.Fatalf("before the first epoch: %q", got)
	}
	if err := s.rotate(); err == nil {
		t.Fatal("rotate hid the write failure")
	}
	if got := s.unpublished(); !strings.Contains(got, "could not publish") || !strings.Contains(got, "Access is denied") {
		t.Fatalf("after a failed write: %q", got)
	}
	ready := []routeOnlyReadiness{{Connector: "claudecode", Ready: true}, {Connector: "codex", Problem: "own problem"}}
	out := withRouteEpochReadiness(ready, s.unpublished())
	if out[0].Ready || !strings.Contains(out[0].Problem, "cannot render route-only") || out[0].Fix == "" {
		t.Fatalf("claudecode = %+v", out[0])
	}
	if out[1].Ready || out[1].Problem != "own problem" {
		t.Fatalf("an existing problem is kept: %+v", out[1])
	}
	s.write = func(string, connector.RouteEpoch) error { return nil }
	if err := s.publishLocked(); err != nil || s.unpublished() != "" {
		t.Fatalf("published: %v %q", err, s.unpublished())
	}
	if got := withRouteEpochReadiness([]routeOnlyReadiness{{Connector: "claudecode", Ready: true}}, ""); !got[0].Ready {
		t.Fatal("a published epoch changes nothing")
	}
	var none *routeEpochState
	if none.unpublished() != "" {
		t.Fatal("off Windows managed hosts there is no epoch problem")
	}
}
