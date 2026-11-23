// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pendingFiles(t *testing.T, s *Store) int {
	t.Helper()
	ents, err := os.ReadDir(s.pendingDir())
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func exposedOnDisk(t *testing.T, s *Store) bool {
	t.Helper()
	b, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), `"exposed": true`)
}

// A pending exposure (recorded while the vault could not be written)
// reads as exposed at once, keeps the value from any sandbox, and the next
// change of the vault writes it and removes the record. The record holds
// no value.
func TestPendingExposureReadsExposedAndIsWrittenByTheNextChange(t *testing.T) {
	s := newStore(t)
	v := fakeStripe()
	c, err := s.Capture(CaptureInput{Value: v, Kind: "stripe-secret-key", Sandbox: "dc-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm(c.Entry.Name); err != nil {
		t.Fatal(err)
	}
	if _, got, err := s.Resolve(c.Entry.Name); err != nil || got != v {
		t.Fatalf("ready entry did not resolve: %v", err)
	}
	f, err := s.read()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordPending(f, []string{v, v}); err != nil {
		t.Fatal(err)
	}
	if n := pendingFiles(t, s); n != 1 {
		t.Fatalf("pending records = %d, want 1 (deduped)", n)
	}
	ents, _ := os.ReadDir(s.pendingDir())
	raw, _ := os.ReadFile(filepath.Join(s.pendingDir(), ents[0].Name()))
	if strings.Contains(string(raw), v) {
		t.Fatal("a pending record holds the value")
	}
	if e, _ := s.Get(c.Entry.Name); !e.Exposed {
		t.Fatal("a pending exposure does not read as exposed")
	}
	if _, _, err := s.Resolve(c.Entry.Name); !errors.Is(err, ErrExposed) {
		t.Fatalf("resolve of a pending exposure = %v, want ErrExposed", err)
	}
	if exposedOnDisk(t, s) {
		t.Fatal("the vault file was written")
	}
	if err := s.ApplyPendingExposures(CaptureWait); err != nil {
		t.Fatal(err)
	}
	if !exposedOnDisk(t, s) || pendingFiles(t, s) != 0 {
		t.Fatalf("after the write: exposed on disk %v, records %d", exposedOnDisk(t, s), pendingFiles(t, s))
	}
}

// A value the vault did not hold when its exposure was recorded is stored
// exposed by the change that stores it later (a person who pastes it into
// a prompt cannot make it usable by confirming it).
func TestPendingExposureOfAValueStoredLater(t *testing.T) {
	s := newStore(t)
	v := fakeGitHub()
	if err := s.recordPending(nil, []string{v}); err != nil {
		t.Fatal(err)
	}
	c, err := s.Capture(CaptureInput{Value: v, Kind: "github-token"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Entry.Exposed || !exposedOnDisk(t, s) || pendingFiles(t, s) != 0 {
		t.Fatalf("stored %+v, on disk %v, records %d", c.Entry, exposedOnDisk(t, s), pendingFiles(t, s))
	}
	if _, err := s.Confirm(c.Entry.Name); !errors.Is(err, ErrExposed) {
		t.Fatalf("confirm of an exposed capture = %v, want ErrExposed", err)
	}
	if _, _, err := s.Resolve(c.Entry.Name); !errors.Is(err, ErrExposed) {
		t.Fatalf("resolve = %v, want ErrExposed", err)
	}
}

// A sealed vault: the gateway (no key) records the value's fingerprint
// with it, so the gateway's next write applies it; the CLI with the key
// refuses the value either way.
func TestPendingExposureInASealedVault(t *testing.T) {
	ks := newFakeKeys()
	cli := sealedStore(t, ks)
	v := fakeAnthropic()
	if _, err := cli.Add(AddInput{Name: "ANTHROPIC_API_KEY", Value: v, Host: "api.anthropic.com"}); err != nil {
		t.Fatal(err)
	}
	gw := withClock(Open(cli.Dir()))
	f, err := gw.read()
	if err != nil || f.sealer == nil {
		t.Fatalf("not sealed: %v", err)
	}
	if err := gw.recordPending(f, []string{v}); err != nil {
		t.Fatal(err)
	}
	if e, _ := gw.Get("ANTHROPIC_API_KEY"); !e.Exposed {
		t.Fatal("the gateway does not read the pending exposure")
	}
	if _, _, err := cli.Resolve("ANTHROPIC_API_KEY"); !errors.Is(err, ErrExposed) {
		t.Fatalf("resolve = %v, want ErrExposed", err)
	}
	if err := gw.ApplyPendingExposures(CaptureWait); err != nil {
		t.Fatal(err)
	}
	if !exposedOnDisk(t, gw) || pendingFiles(t, gw) != 0 {
		t.Fatal("the gateway did not write the exposure")
	}
	// A record without a fingerprint (the vault was unread) still keeps
	// the value from the CLI, which opens it.
	v2 := fakeGitHub()
	if _, err := cli.Add(AddInput{Name: "GITHUB_TOKEN", Value: v2, Host: "api.github.com"}); err != nil {
		t.Fatal(err)
	}
	if err := gw.recordPending(nil, []string{v2}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cli.Resolve("GITHUB_TOKEN"); !errors.Is(err, ErrExposed) {
		t.Fatalf("resolve without a fingerprint = %v, want ErrExposed", err)
	}
}

// The pending exposures are bounded.
func TestPendingExposuresAreBounded(t *testing.T) {
	s := newStore(t)
	for i := 0; i < MaxPendingExposures; i++ {
		if err := s.recordPending(nil, []string{fmt.Sprintf("%s%04d", fakeGitHub(), i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.recordPending(nil, []string{fakeStripe()}); err == nil {
		t.Fatal("a pending exposure past the bound was recorded")
	}
}

// One sandbox's prompts hold at most half of the prompt room, so a
// process in one sandbox cannot fill the room every other sandbox needs;
// each entry says which sandbox it came from.
func TestPromptCapturesFromOneSandboxAreBounded(t *testing.T) {
	s := newStore(t)
	value := func(i int) string { return fmt.Sprintf("%s%04d", fakeGitHub(), i) }
	for i := 0; i < MaxCapturedPerSandbox; i++ {
		c, err := s.Capture(CaptureInput{Value: value(i), Kind: "github-token", Sandbox: "dc-a"})
		if err != nil || c.Entry.Sandbox != "dc-a" {
			t.Fatalf("capture %d = %+v (%v)", i, c.Entry, err)
		}
	}
	_, err := s.Capture(CaptureInput{Value: value(100), Kind: "github-token", Sandbox: "dc-a"})
	if !errors.Is(err, ErrSandboxCaptureFull) || !errors.Is(err, ErrCaptureFull) ||
		!strings.Contains(err.Error(), "defenseclaw sandbox vault list") {
		t.Fatalf("capture past the sandbox share = %v", err)
	}
	if _, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key", Sandbox: "dc-b"}); err != nil {
		t.Fatalf("another sandbox's prompt was refused: %v", err)
	}
	// A confirmed entry no longer counts.
	if _, err := s.Confirm("GITHUB_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Capture(CaptureInput{Value: value(101), Kind: "github-token", Sandbox: "dc-a"}); err != nil {
		t.Fatalf("capture after a confirm = %v", err)
	}
	// Tool calls and output have their own bound.
	if _, err := s.Capture(CaptureInput{Value: fakeAnthropic(), Kind: "anthropic-key", Sandbox: "dc-a", FromModel: true, Exposed: true}); err != nil {
		t.Fatalf("model capture = %v", err)
	}
}
