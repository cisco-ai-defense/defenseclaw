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

// GAP-1979: nothing tells a sandbox's forged hook events from its
// harness's, so each sandbox fills only its own room. Two sandboxes that
// fill all of theirs, prompt and model side, with values of one kind leave
// a third sandbox, captures with no sandbox, and the person's own adds
// untouched, and the third sandbox's value of that kind still gets a name.
// It also pins the documented limit that remains (rel-1-0-10:GAP-2105): with
// no harness-attested event channel, a sandbox's own forged events can fill
// its own room, after which its genuine prompt is refused with
// ErrSandboxCaptureFull (the prompt is still stopped, fail closed).
func TestOneSandboxCannotFillAnotherSandboxsRoom(t *testing.T) {
	s := newStore(t)
	value := func(sb string, i int) string { return fmt.Sprintf("%s%s%04d", fakeStripe(), sb, i) }
	for _, sb := range []string{"a", "b"} {
		name := "dc-" + sb
		for i := 0; i < MaxCapturedPerSandbox; i++ {
			if _, err := s.Capture(CaptureInput{Value: value(sb, i), Kind: "stripe-secret-key", Sandbox: name}); err != nil {
				t.Fatalf("%s prompt %d: %v", name, i, err)
			}
		}
		for i := 0; i < MaxCapturedFromModelPerSandbox; i++ {
			if _, err := s.Capture(CaptureInput{Value: value(sb, 100+i), Kind: "stripe-secret-key", Sandbox: name, FromModel: true, Exposed: true}); err != nil {
				t.Fatalf("%s model %d: %v", name, i, err)
			}
		}
		_, err := s.Capture(CaptureInput{Value: value(sb, 200), Kind: "stripe-secret-key", Sandbox: name})
		if !errors.Is(err, ErrSandboxCaptureFull) || !errors.Is(err, ErrCaptureFull) || !strings.Contains(err.Error(), "this sandbox") {
			t.Fatalf("%s prompt past its room = %v", name, err)
		}
		_, err = s.Capture(CaptureInput{Value: value(sb, 201), Kind: "stripe-secret-key", Sandbox: name, FromModel: true, Exposed: true})
		if !errors.Is(err, ErrSandboxModelCaptureFull) || !errors.Is(err, ErrModelCaptureFull) || !strings.Contains(err.Error(), "this sandbox") {
			t.Fatalf("%s model past its room = %v", name, err)
		}
	}
	c, err := s.Capture(CaptureInput{Value: value("c", 0), Kind: "stripe-secret-key", Sandbox: "dc-c"})
	if err != nil || c.Entry.Name != fmt.Sprintf("STRIPE_API_KEY_%d", 2*(MaxCapturedPerSandbox+MaxCapturedFromModelPerSandbox)+1) {
		t.Fatalf("third sandbox's prompt = %+v (%v)", c.Entry, err)
	}
	if _, err := s.Capture(CaptureInput{Value: value("c", 1), Kind: "stripe-secret-key", Sandbox: "dc-c", FromModel: true, Exposed: true}); err != nil {
		t.Fatalf("third sandbox's tool call = %v", err)
	}
	if _, err := s.Capture(CaptureInput{Value: value("n", 0), Kind: "stripe-secret-key"}); err != nil {
		t.Fatalf("capture with no sandbox = %v", err)
	}
	if _, err := s.Add(AddInput{Name: "MY_STRIPE", Value: value("p", 0), Host: "api.stripe.com"}); err != nil {
		t.Fatalf("the person's own add = %v", err)
	}
}

// All captures together stop at MaxCapturedTotal, so the person's own
// room is kept however many sandboxes fill their own (review of GAP-1979):
// three full sandboxes reach it, a fourth is refused with the all-captures
// message, and the person's add still succeeds.
func TestCapturesFromManySandboxesKeepThePersonsRoom(t *testing.T) {
	s := newStore(t)
	per := MaxCapturedPerSandbox + MaxCapturedFromModelPerSandbox
	full := MaxCapturedTotal / per
	if full*per != MaxCapturedTotal || full < 2 {
		t.Fatalf("test assumes whole sandboxes fill the total: %d per sandbox, total %d", per, MaxCapturedTotal)
	}
	value := func(sb, i int) string { return fmt.Sprintf("%s%02d%04d", fakeStripe(), sb, i) }
	for sb := 0; sb < full; sb++ {
		name := fmt.Sprintf("dc-%d", sb)
		for i := 0; i < MaxCapturedPerSandbox; i++ {
			if _, err := s.Capture(CaptureInput{Value: value(sb, i), Kind: "stripe-secret-key", Sandbox: name}); err != nil {
				t.Fatalf("%s prompt %d: %v", name, i, err)
			}
		}
		for i := 0; i < MaxCapturedFromModelPerSandbox; i++ {
			if _, err := s.Capture(CaptureInput{Value: value(sb, 100+i), Kind: "stripe-secret-key", Sandbox: name, FromModel: true, Exposed: true}); err != nil {
				t.Fatalf("%s model %d: %v", name, i, err)
			}
		}
	}
	_, err := s.Capture(CaptureInput{Value: value(99, 0), Kind: "stripe-secret-key", Sandbox: "dc-late"})
	if !errors.Is(err, ErrAllCapturesFull) || !errors.Is(err, ErrCaptureFull) || !strings.Contains(err.Error(), "defenseclaw sandbox vault list") {
		t.Fatalf("capture past the total = %v", err)
	}
	_, err = s.Capture(CaptureInput{Value: value(99, 1), Kind: "stripe-secret-key"})
	if !errors.Is(err, ErrAllCapturesFull) {
		t.Fatalf("capture with no sandbox past the total = %v", err)
	}
	for i := 0; i < MaxEntries-MaxCapturedTotal; i++ {
		if _, err := s.Add(AddInput{Name: fmt.Sprintf("MINE_%d", i), Value: value(98, i), Host: "api.stripe.com"}); err != nil {
			t.Fatalf("the person's own add %d = %v", i, err)
		}
	}
	// A confirmed capture is the person's own: it frees capture room.
	if _, err := s.Confirm("STRIPE_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(); len(list) != MaxEntries {
		t.Fatalf("entries = %d, want MaxEntries", len(list))
	}
}

// A pending exposure that cannot be read fails every read closed: an
// exposure is never skipped, so no value is handed out past it.
func TestUnreadablePendingExposureFailsClosed(t *testing.T) {
	s := newStore(t)
	if _, err := s.Add(AddInput{Name: "STRIPE_LIVE", Value: fakeStripe(), Host: "api.stripe.com"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.pendingDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.pendingDir(), "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Resolve("STRIPE_LIVE"); err == nil || !strings.Contains(err.Error(), "pending exposure") {
		t.Fatalf("resolve with an unreadable record = %v", err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("list read past an unreadable record")
	}
	// A record being written (safefile's temporary file) is not read.
	if err := os.Remove(filepath.Join(s.pendingDir(), "broken.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.pendingDir(), ".safefile-x.json-123"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Resolve("STRIPE_LIVE"); err != nil {
		t.Fatalf("resolve beside a temporary file = %v", err)
	}
}

// A value the model saw that the vault refused to store (its limit for
// tool calls and output is reached) is recorded pending, so a later
// capture of it from a prompt is stored exposed.
func TestRefusedExposedValueIsStoredExposedLater(t *testing.T) {
	s := newStore(t)
	for i := 0; i < MaxCapturedFromModel; i++ {
		if _, err := s.Capture(CaptureInput{Value: fmt.Sprintf("%s%04d", fakeGitHub(), i), Kind: "github-token", Exposed: true, FromModel: true}); err != nil {
			t.Fatal(err)
		}
	}
	v := fakeStripe()
	if _, err := s.Capture(CaptureInput{Value: v, Kind: "stripe-secret-key", Exposed: true, FromModel: true}); !errors.Is(err, ErrModelCaptureFull) {
		t.Fatalf("capture past the model bound = %v", err)
	}
	if pendingFiles(t, s) != 1 {
		t.Fatalf("pending records = %d, want 1", pendingFiles(t, s))
	}
	c, err := s.Capture(CaptureInput{Value: v, Kind: "stripe-secret-key"})
	if err != nil || !c.Entry.Exposed {
		t.Fatalf("later prompt capture = %+v (%v)", c.Entry, err)
	}
}

// One call records at most a bounded number of pending exposures.
func TestPendingExposuresPerCallAreBounded(t *testing.T) {
	s := newStore(t)
	var values []string
	for i := 0; i <= maxPendingPerCall; i++ {
		values = append(values, fmt.Sprintf("%s%04d", fakeGitHub(), i))
	}
	if err := s.recordPending(nil, values); err == nil || pendingFiles(t, s) != 0 {
		t.Fatalf("an oversized call recorded %d (%v)", pendingFiles(t, s), err)
	}
}
