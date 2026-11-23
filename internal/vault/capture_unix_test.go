// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package vault

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

// A capture that changes nothing neither waits for the lock nor writes;
// a busy lock still returns the values the vault holds.
func TestCaptureThatChangesNothingSkipsTheLockAndTheWrite(t *testing.T) {
	s := newStore(t)
	if _, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, FromModel: true}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDir(s.Dir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	out, err := s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, FromModel: true}}, 50*time.Millisecond)
	if err != nil || len(out) != 1 || out[0].Entry.Name != "STRIPE_API_KEY" || out[0].New {
		t.Fatalf("an unchanged capture under a held lock = %+v (%v)", out, err)
	}
	after, err := os.ReadFile(s.Path())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("an unchanged capture rewrote the vault (%v)", err)
	}
	if _, err := s.CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, 50*time.Millisecond); !errors.Is(err, ErrBusy) {
		t.Fatalf("a new value under a held lock = %v", err)
	}
}

// A busy lock writes nothing but still names the held values, so the
// caller can tag them and retry their exposure.
func TestCaptureBusyNamesTheHeldValues(t *testing.T) {
	s := newStore(t)
	if _, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key"}); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDir(s.Dir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, FromModel: true}}, 50*time.Millisecond)
	unlock()
	if !errors.Is(err, ErrBusy) || len(out) != 1 || out[0].Entry.Name != "STRIPE_API_KEY" {
		t.Fatalf("busy capture = %+v (%v)", out, err)
	}
	if !errors.Is(err, ErrExposurePending) {
		t.Fatalf("busy capture did not record the exposure pending: %v", err)
	}
	if raw, _ := os.ReadFile(s.Path()); bytes.Contains(raw, []byte(`"exposed": true`)) {
		t.Fatal("a busy capture wrote")
	}
	// The pending exposure reads as exposed at once: no sandbox gets the
	// value while the vault waits for a write.
	if e, _ := s.Get("STRIPE_API_KEY"); !e.Exposed {
		t.Fatal("a busy capture's exposure does not read as exposed")
	}
	if _, err := s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, KnownOnly: true}}, CaptureWait); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPendingExposures(CaptureWait); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(s.Path()); !bytes.Contains(raw, []byte(`"exposed": true`)) || pendingFiles(t, s) != 0 {
		t.Fatal("the retried exposure was not written")
	}
}

// A busy capture of an exposed value while the vault lock is held keeps
// the value from any sandbox at once, before any write.
func TestBusyExposureKeepsTheValueFromASandbox(t *testing.T) {
	s := newStore(t)
	c, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm(c.Entry.Name); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDir(s.Dir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	_, err = s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, KnownOnly: true}}, 20*time.Millisecond)
	if !errors.Is(err, ErrBusy) || !errors.Is(err, ErrExposurePending) {
		t.Fatalf("busy exposure = %v", err)
	}
	if _, _, err := s.Resolve(c.Entry.Name); !errors.Is(err, ErrExposed) {
		t.Fatalf("resolve while the lock is held = %v, want ErrExposed", err)
	}
}
