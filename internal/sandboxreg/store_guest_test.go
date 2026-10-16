// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxreg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuestSightingPersistsOnceForWatchedBoundRegistration(t *testing.T) {
	s, clock, dir := newTestStore(t)
	r := pending(t)
	if err := s.Create(1001, r); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkGuestSeen(1001, r.ID, clock.t); !errors.Is(err, ErrNotPending) {
		t.Fatalf("pending sighting: %v", err)
	}
	bound, err := s.Bind(1001, r.ID, bind(1))
	if err != nil || !bound.GuestWatch || !bound.GuestSeenAt.IsZero() {
		t.Fatalf("bind watch: %+v %v", bound, err)
	}
	if err := s.MarkGuestSeen(1002, r.ID, clock.t); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account: %v", err)
	}
	if err := s.MarkGuestSeen(1001, r.ID, clock.t.Add(-time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pre-bind sighting: %v", err)
	}
	first := clock.t.Add(time.Second)
	if err := s.MarkGuestSeen(1001, r.ID, first); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkGuestSeen(1001, r.ID, first.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reopened := NewFileStore(dir)
	got, ok, err := reopened.Get(1001, r.ID)
	if err != nil || !ok || !got.GuestSeenAt.Equal(first) {
		t.Fatalf("reopened sighting: %+v %v %v", got, ok, err)
	}
	if err := reopened.Revoke(1001, r.ID, ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	if err := reopened.MarkGuestSeen(1001, r.ID, first.Add(time.Hour)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked sighting: %v", err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "1001.json"))
	if err != nil || !strings.Contains(string(blob), `"guest_seen_at"`) {
		t.Fatalf("stored sighting: %v %s", err, blob)
	}
}

func TestOlderRegistrationWithoutGuestFieldsDecodesUnwatched(t *testing.T) {
	old := `{"v":1,"id":"reg-abcdefghijklmnopqrstuvwxyz","uid":1001,"user_name":"alice","state":"live","sandbox_id":"sbx-1","sandbox_name":"box","bound_at":"2026-10-14T00:00:00Z"}`
	var r Registration
	if err := json.Unmarshal([]byte(old), &r); err != nil {
		t.Fatal(err)
	}
	if r.GuestWatch || !r.GuestSeenAt.IsZero() || r.SandboxName != "box" {
		t.Fatalf("old registration changed: %+v", r)
	}
}
