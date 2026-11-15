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

// Readiness also reads the published epoch back: a missing, unreadable or
// different file leaves every account unrendered even though the write
// returned success. No live call is made.
func TestRouteOnlyReadinessReadsThePublishedRouteEpochBack(t *testing.T) {
	var onDisk *connector.RouteEpoch
	var loadErr error
	s := &routeEpochState{dataDir: func() string { return "fixture-dir" }, seen: map[string]bool{},
		write: func(_ string, e connector.RouteEpoch) error { c := e; onDisk = &c; return nil },
		load:  func(string) (*connector.RouteEpoch, error) { return onDisk, loadErr }}
	if err := s.rotate(); err != nil || s.unpublished() != "" {
		t.Fatalf("published and readable: %v %q", err, s.unpublished())
	}
	onDisk = nil
	if got := s.unpublished(); !strings.Contains(got, "file is missing") {
		t.Fatalf("missing file: %q", got)
	}
	loadErr = errors.New("route epoch fixture: not a private file")
	if got := s.unpublished(); !strings.Contains(got, "cannot be read") || !strings.Contains(got, "not a private file") {
		t.Fatalf("unreadable file: %q", got)
	}
	loadErr = nil
	other, err := connector.NewRouteEpoch()
	if err != nil {
		t.Fatal(err)
	}
	onDisk = &other
	if got := s.unpublished(); !strings.Contains(got, "not the one this gateway accepts") {
		t.Fatalf("different epoch: %q", got)
	}
	out := withRouteEpochReadiness([]routeOnlyReadiness{{Connector: "codex", Ready: true}}, s.unpublished())
	if out[0].Ready || out[0].Cause != routeCauseEpoch || !strings.Contains(out[0].Problem, "not the one this gateway accepts") {
		t.Fatalf("readiness: %+v", out[0])
	}
}

// routrev round 1 P3: an epoch rotated between the copy and the read-back
// must not leave the connector not ready until the next recheck.
func TestPublishedRouteEpochRotationBetweenCopyAndReadBackIsNotAProblem(t *testing.T) {
	var s *routeEpochState
	var onDisk *connector.RouteEpoch
	first := true
	s = &routeEpochState{dataDir: func() string { return "fixture-dir" }, seen: map[string]bool{},
		write: func(_ string, e connector.RouteEpoch) error { c := e; onDisk = &c; return nil }}
	s.load = func(string) (*connector.RouteEpoch, error) {
		if first {
			first = false
			// The gateway rotates (and publishes) right after the copy was taken.
			if err := s.rotate(); err != nil {
				t.Fatal(err)
			}
		}
		return onDisk, nil
	}
	if err := s.rotate(); err != nil {
		t.Fatal(err)
	}
	if got := s.unpublished(); got != "" {
		t.Fatalf("a rotation during the read-back reported %q", got)
	}
}
