// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Values are built at run time: no credential-shaped literal in the tree.
func capStripe(i int) string {
	return "sk" + "_live_" + strings.Repeat("Qq", 12) + fmt.Sprintf("%04d", i)
}
func capGitHub(i int) string { return "gh" + "p_" + strings.Repeat("Ww", 16) + fmt.Sprintf("%04d", i) }
func capOpenAI(i int) string {
	return "sk-" + "proj-" + strings.Repeat("Ee7Rr", 8) + fmt.Sprintf("%04d", i)
}

// A value the vault holds is marked exposed even when the new values of
// the same call cannot be stored: a ready entry an agent's model has seen
// never stays usable because the vault was full.
func TestCaptureExposesHeldValuesWhenNewOnesCannotBeStored(t *testing.T) {
	for _, full := range []string{"prompt", "model", "entries"} {
		t.Run(full, func(t *testing.T) {
			s := newStore(t)
			ready := fakeStripe()
			if _, err := s.Add(AddInput{Name: "STRIPE_LIVE", Value: ready, Host: "api.stripe.com"}); err != nil {
				t.Fatal(err)
			}
			var newIn CaptureInput
			var wantErr error
			switch full {
			case "prompt":
				for i := 0; i < MaxCaptured; i++ {
					kind, v := "github-token", capGitHub(i)
					if i >= 8 {
						kind, v = "openai-key", capOpenAI(i)
					}
					if _, err := s.Capture(CaptureInput{Value: v, Kind: kind}); err != nil {
						t.Fatalf("prompt capture %d: %v", i, err)
					}
				}
				newIn, wantErr = CaptureInput{Value: fakeAnthropic(), Kind: "anthropic-key"}, ErrCaptureFull
			case "model":
				for i := 0; i < MaxCapturedFromModel; i++ {
					if _, err := s.Capture(CaptureInput{Value: capGitHub(i), Kind: "github-token", Exposed: true, FromModel: true}); err != nil {
						t.Fatalf("model capture %d: %v", i, err)
					}
				}
				newIn, wantErr = CaptureInput{Value: fakeAnthropic(), Kind: "anthropic-key", Exposed: true, FromModel: true}, ErrModelCaptureFull
			case "entries":
				for i := 1; i < MaxEntries; i++ {
					if _, err := s.Add(AddInput{Name: fmt.Sprintf("M%02d", i), Value: fmt.Sprintf("manual-value-%02d", i), Host: "api.example.com"}); err != nil {
						t.Fatalf("add %d: %v", i, err)
					}
				}
				newIn, wantErr = CaptureInput{Value: fakeAnthropic(), Kind: "anthropic-key", Exposed: true, FromModel: true}, ErrFull
			}
			out, err := s.CaptureAll([]CaptureInput{
				{Value: ready, Kind: "stripe-secret-key", Exposed: true, FromModel: true}, newIn,
			}, CaptureWait)
			if !errors.Is(err, wantErr) {
				t.Fatalf("err = %v, want %v", err, wantErr)
			}
			if len(out) != 2 || out[0].Entry.Name != "STRIPE_LIVE" || !out[0].Entry.Exposed || out[1].Entry.Name != "" {
				t.Fatalf("out = %+v", out)
			}
			e, err := s.Get("STRIPE_LIVE")
			if err != nil || !e.Exposed || e.Status() != StatusExposed {
				t.Fatalf("held entry after a partial capture = %+v (%v)", e, err)
			}
			if _, _, err := s.Resolve("STRIPE_LIVE"); !errors.Is(err, ErrExposed) {
				t.Fatalf("an exposed entry resolved: %v", err)
			}
		})
	}
}

// Model-side captures have their own bound: a session whose tools keep
// printing token-shaped values never uses up the room prompts need.
func TestModelCapturesNeverFillThePromptRoom(t *testing.T) {
	s := newStore(t)
	for i := 0; i < MaxCapturedFromModel; i++ {
		if _, err := s.Capture(CaptureInput{Value: capGitHub(i), Kind: "github-token", Exposed: true, FromModel: true}); err != nil {
			t.Fatalf("model capture %d: %v", i, err)
		}
	}
	if _, err := s.Capture(CaptureInput{Value: capGitHub(99), Kind: "github-token", Exposed: true, FromModel: true}); !errors.Is(err, ErrModelCaptureFull) {
		t.Fatalf("a model capture past its bound = %v", err)
	}
	for i := 0; i < MaxCaptured; i++ {
		kind, v := "stripe-secret-key", capStripe(i)
		if i >= 9 {
			kind, v = "openai-key", capOpenAI(i)
		}
		if _, err := s.Capture(CaptureInput{Value: v, Kind: kind}); err != nil {
			t.Fatalf("prompt capture %d with the model bound reached: %v", i, err)
		}
	}
	if _, err := s.Capture(CaptureInput{Value: fakeAnthropic(), Kind: "anthropic-key"}); !errors.Is(err, ErrCaptureFull) {
		t.Fatalf("a prompt capture past its bound = %v", err)
	}
	// A confirmed entry is the person's own and no longer counts.
	if _, err := s.Confirm("STRIPE_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Capture(CaptureInput{Value: fakeAnthropic(), Kind: "anthropic-key"}); err != nil {
		t.Fatalf("a prompt capture after a confirm: %v", err)
	}
	e, err := s.Get("GITHUB_TOKEN")
	if err != nil || !e.FromModel || e.Source != SourceCaptured {
		t.Fatalf("model entry = %+v (%v)", e, err)
	}
}

// A reply or another event stores nothing new: KnownOnly only marks a held
// value exposed.
func TestKnownOnlyCaptureStoresNothingNew(t *testing.T) {
	s := newStore(t)
	out, err := s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, FromModel: true, KnownOnly: true}}, CaptureWait)
	if err != nil || len(out) != 1 || out[0].Entry.Name != "" {
		t.Fatalf("out = %+v (%v)", out, err)
	}
	if _, err := os.Stat(s.Dir()); !os.IsNotExist(err) {
		t.Fatalf("a capture that stores nothing touched the vault directory: %v", err)
	}
	if _, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key"}); err != nil {
		t.Fatal(err)
	}
	out, err = s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, KnownOnly: true}}, CaptureWait)
	if err != nil || out[0].Entry.Name != "STRIPE_API_KEY" || !out[0].Entry.Exposed {
		t.Fatalf("out = %+v (%v)", out, err)
	}
}

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
	if e, _ := s.Get("STRIPE_API_KEY"); e.Exposed {
		t.Fatal("a busy capture wrote")
	}
	if _, err := s.CaptureAll([]CaptureInput{{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true, KnownOnly: true}}, CaptureWait); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.Get("STRIPE_API_KEY"); !e.Exposed {
		t.Fatal("the retried exposure was not written")
	}
}
