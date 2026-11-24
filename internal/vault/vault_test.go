// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Test values are built at run time so no credential-shaped literal sits in
// the source tree.
func fakeAnthropic() string { return "sk-" + "ant-api03-" + strings.Repeat("aB3dE5", 8) }
func fakeStripe() string    { return "sk" + "_live_" + strings.Repeat("Zx9Qw2", 5) }
func fakeGitHub() string    { return "gh" + "p_" + strings.Repeat("Ab1Cd2", 6) }

func newStore(t *testing.T) *Store {
	t.Helper()
	s := Open(filepath.Join(t.TempDir(), "vault"))
	clock := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	return s
}

func TestAddListNeverReturnsValues(t *testing.T) {
	s := newStore(t)
	e, err := s.Add(AddInput{Name: "STRIPE_API_KEY", Value: fakeStripe(), Host: "api.stripe.com"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status() != StatusReady || e.Target() != "api.stripe.com" || e.Source != SourceManual {
		t.Fatalf("entry = %+v", e)
	}
	list, err := s.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	// Entry has no value field at all; prove the JSON a caller would print
	// carries none either.
	if b, _ := jsonOf(list); strings.Contains(b, fakeStripe()) {
		t.Fatal("list output carries the value")
	}
	got, value, err := s.Resolve("STRIPE_API_KEY")
	if err != nil || value != fakeStripe() || got.Host != "api.stripe.com" || got.Port != 443 {
		t.Fatalf("resolve = %+v %v %v", got, value != "", err)
	}
}

func TestFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	s := newStore(t)
	if _, err := s.Add(AddInput{Name: "A", Value: "secret-value-1", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault file mode = %v", fi.Mode().Perm())
	}
	di, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("vault dir mode = %v", di.Mode().Perm())
	}
}

func TestAddRefusesBadInput(t *testing.T) {
	s := newStore(t)
	cases := []AddInput{
		{Name: "1BAD", Value: "v", Host: "api.example.com"},
		{Name: "DEFENSECLAW" + "_TOKEN", Value: "v", Host: "api.example.com"},
		{Name: "OK", Value: "", Host: "api.example.com"},
		{Name: "OK", Value: "a\nb", Host: "api.example.com"},
		{Name: "OK", Value: " padded", Host: "api.example.com"},
		{Name: "OK", Value: "v", Host: "https://api.example.com"},
		{Name: "OK", Value: "v", Host: "*.example.com"},
		{Name: "OK", Value: "v", Host: "user@api.example.com"},
		{Name: "OK", Value: "v", Host: "api.example.com:0"},
		{Name: "OK", Value: "v", Host: "intranet"},
		{Name: "OK", Value: strings.Repeat("x", MaxValueBytes+1), Host: "api.example.com"},
	}
	for _, c := range cases {
		if _, err := s.Add(c); err == nil {
			t.Errorf("Add(%q, host %q) accepted", c.Name, c.Host)
		}
	}
	if _, err := s.Add(AddInput{Name: "OK", Value: "v1", Host: "API.Example.com.:8443"}); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Get("OK")
	if e.Host != "api.example.com" || e.Port != 8443 || e.Target() != "api.example.com:8443" {
		t.Fatalf("host normalized = %+v", e)
	}
	if _, err := s.Add(AddInput{Name: "OK", Value: "v2", Host: "api.example.com"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name err = %v", err)
	}
}

func TestReplaceBindRenameRemove(t *testing.T) {
	s := newStore(t)
	if _, err := s.Add(AddInput{Name: "KEY", Value: "old-value", Source: SourceCaptured, Exposed: true}); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Get("KEY")
	if e.Status() != StatusExposed {
		t.Fatalf("status = %s", e.Status())
	}
	if e, _ = s.ReplaceValue("KEY", "new-value"); e.Exposed {
		t.Fatal("replace kept exposed")
	}
	if e.Status() != StatusNeedsHost {
		t.Fatalf("status = %s", e.Status())
	}
	if _, _, err := s.Resolve("KEY"); !errors.Is(err, ErrNoHost) {
		t.Fatalf("resolve unbound err = %v", err)
	}
	if _, err := s.Bind("KEY", "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, v, err := s.Resolve("KEY"); err != nil || v != "new-value" {
		t.Fatalf("resolve = %v", err)
	}
	if _, err := s.Rename("KEY", "NEW_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("KEY"); !IsNotFound(err) {
		t.Fatalf("old name still there: %v", err)
	}
	if err := s.Remove("NEW_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("NEW_KEY"); !IsNotFound(err) {
		t.Fatalf("second remove err = %v", err)
	}
	b, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "new-value") {
		t.Fatal("removed value is still on disk")
	}
}

func TestMarkUsed(t *testing.T) {
	s := newStore(t)
	_, _ = s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"})
	if err := s.MarkUsed([]string{"A", "MISSING"}, "demo"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Get("A")
	if e.UseCount != 1 || e.LastUsedBy != "demo" || e.LastUsedAt == nil {
		t.Fatalf("usage = %+v", e)
	}
}

func TestFindCapturableAndRedact(t *testing.T) {
	text := "use " + fakeAnthropic() + " and " + fakeStripe() + " but not AKIA" + "IOSFODNN7EXAMPLE or sk-short"
	found := FindCapturable(text)
	if len(found) != 2 || found[0].Kind != "anthropic-key" || found[1].Kind != "stripe-secret-key" {
		t.Fatalf("found = %+v", found)
	}
	if text[found[0].Start:found[0].End] != fakeAnthropic() {
		t.Fatal("anthropic span is not the whole key")
	}
	red := Redact(text, found, map[string]string{fakeAnthropic(): "ANTHROPIC_API_KEY"})
	if strings.Contains(red, fakeAnthropic()) || strings.Contains(red, fakeStripe()) {
		t.Fatalf("redacted text still holds a value: %s", red)
	}
	if !strings.Contains(red, "[vault:ANTHROPIC_API_KEY]") || !strings.Contains(red, "[vault:redacted]") {
		t.Fatalf("redacted = %s", red)
	}
	if FindCapturable("sk-"+strings.Repeat("a", 40)) != nil {
		t.Fatal("a repeated-character placeholder was captured")
	}
}

func TestCaptureNamesDedupesAndExposes(t *testing.T) {
	s := newStore(t)
	c, err := s.Capture(CaptureInput{Value: fakeGitHub(), Kind: "github-token", From: "claudecode prompt in sandbox demo"})
	if err != nil || !c.New {
		t.Fatalf("capture = %+v %v", c, err)
	}
	if c.Entry.Name != "GITHUB_TOKEN" || c.Entry.Target() != "api.github.com" || c.Entry.Source != SourceCaptured || c.Entry.Status() != StatusUnconfirmed {
		t.Fatalf("entry = %+v", c.Entry)
	}
	// Same value again, now exposed by a tool call: no new entry, marked exposed.
	c2, err := s.Capture(CaptureInput{Value: fakeGitHub(), Kind: "github-token", Exposed: true})
	if err != nil || c2.New || c2.Entry.Name != "GITHUB_TOKEN" || c2.Entry.Status() != StatusExposed {
		t.Fatalf("recapture = %+v %v", c2, err)
	}
	// A different value of the same kind gets _2.
	other := "gh" + "p_" + strings.Repeat("Zz9Yy8", 6)
	c3, err := s.Capture(CaptureInput{Value: other, Kind: "github-token"})
	if err != nil || c3.Entry.Name != "GITHUB_TOKEN_2" {
		t.Fatalf("second token = %+v %v", c3, err)
	}
	// A kind with no obvious API is captured unbound.
	c4, err := s.Capture(CaptureInput{Value: "AIza" + strings.Repeat("Qq1Ww2Ee3", 4)[:35], Kind: "google-api-key"})
	if err != nil || c4.Entry.Status() != StatusUnconfirmed || c4.Entry.Host != "" {
		t.Fatalf("google key = %+v %v", c4, err)
	}
	if _, err := s.Capture(CaptureInput{Value: "AKIA" + "IOSFODNN7EXAMPLE", Kind: "aws-access-key-id"}); err == nil {
		t.Fatal("an AWS key ID was captured")
	}
	if e, found, _ := s.FindByValue(other); !found || e.Name != "GITHUB_TOKEN_2" {
		t.Fatalf("find by value = %+v %v", e, found)
	}
}

func TestCorruptVaultFailsClosed(t *testing.T) {
	s := newStore(t)
	_, _ = s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"})
	if err := os.WriteFile(s.Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("a corrupt vault listed")
	}
	if _, err := s.Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"}); err == nil {
		t.Fatal("a corrupt vault was overwritten")
	}
}

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// A value an agent produced (a tool-call capture) is never handed to a
// sandbox until the person replaces it: an agent cannot plant its own
// token under a real API's name and have a later sandbox use it.
func TestResolveRefusesExposedUntilReplaced(t *testing.T) {
	s := newStore(t)
	c, err := s.Capture(CaptureInput{Value: fakeGitHub(), Kind: "github-token", Exposed: true, From: "claudecode tool call in sandbox sb"})
	if err != nil || c.Entry.Target() != "api.github.com" {
		t.Fatalf("capture = %+v %v", c, err)
	}
	if _, _, err := s.Resolve("GITHUB_TOKEN"); !errors.Is(err, ErrExposed) || !strings.Contains(err.Error(), "sandbox vault replace GITHUB_TOKEN") {
		t.Fatalf("resolve of an exposed entry = %v", err)
	}
	if _, err := s.ReplaceValue("GITHUB_TOKEN", "gh"+"p_"+strings.Repeat("Mm4Nn5", 6)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Resolve("GITHUB_TOKEN"); err != nil {
		t.Fatalf("resolve after replace = %v", err)
	}
}

func TestAddRefusesAValueTheVaultHolds(t *testing.T) {
	s := newStore(t)
	if _, err := s.Add(AddInput{Name: "A", Value: "same-value", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(AddInput{Name: "B", Value: "same-value", Host: "api.example.com"}); err == nil || !strings.Contains(err.Error(), "as A") {
		t.Fatalf("duplicate value = %v", err)
	}
}

// One call's captures are one write; a value past a bound is not stored,
// and the call's other values are.
func TestCaptureAllIsBounded(t *testing.T) {
	s := newStore(t)
	var ins []CaptureInput
	for i := 0; i < MaxCaptured; i++ {
		ins = append(ins, CaptureInput{Value: "sk" + "_live_" + strings.Repeat("Qq", 12) + fmt.Sprintf("%04d", i), Kind: "stripe-secret-key"})
	}
	if _, err := s.CaptureAll(ins[:9], CaptureWait); err != nil {
		t.Fatal(err)
	}
	// Names of a kind run past _9 (GAP-1979): the tenth and eleventh stripe
	// keys are STRIPE_API_KEY_10 and _11.
	if out, err := s.CaptureAll(ins[9:11], CaptureWait); err != nil || out[0].Entry.Name != "STRIPE_API_KEY_10" || out[1].Entry.Name != "STRIPE_API_KEY_11" {
		t.Fatalf("tenth and eleventh keys of one kind: %+v (%v)", out, err)
	}
	other := []CaptureInput{}
	for i := 0; i < MaxCaptured; i++ {
		other = append(other, CaptureInput{Value: "gh" + "p_" + strings.Repeat("Ww", 16) + fmt.Sprintf("%04d", i), Kind: "github-token"})
	}
	if _, err := s.CaptureAll(other[:4], CaptureWait); err != nil {
		t.Fatal(err)
	}
	// The sixteenth fits and the seventeenth does not: one write, the
	// stored value kept and the refused one named in the error.
	out, err := s.CaptureAll(other[4:6], CaptureWait)
	if !errors.Is(err, ErrCaptureFull) || out[0].Entry.Name == "" || out[1].Entry.Name != "" {
		t.Fatalf("capture past the cap = %+v (%v)", out, err)
	}
	if list, _ := s.List(); len(list) != MaxCaptured {
		t.Fatalf("entries after a partial call = %d", len(list))
	}
}

// A JWT whose last segment runs into a key does not hide the key.
func TestFindCapturableIsNotHiddenByOtherShapes(t *testing.T) {
	jwt := "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + "." + strings.Repeat("Sg5Ty6", 4)
	found := FindCapturable(jwt + "-" + fakeAnthropic())
	if len(found) != 1 || found[0].Kind != "anthropic-key" {
		t.Fatalf("found = %+v", found)
	}
}

// Replacing an exposed value with the same value does not lift the
// exposure: only a new value does.
func TestReplaceWithTheSameExposedValueIsRefused(t *testing.T) {
	s := newStore(t)
	if _, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceValue("STRIPE_API_KEY", fakeStripe()); !errors.Is(err, ErrExposed) {
		t.Fatalf("same-value replace = %v", err)
	}
	if e, _ := s.Get("STRIPE_API_KEY"); !e.Exposed {
		t.Fatal("exposure lifted by a same-value replace")
	}
	if _, err := s.ReplaceValue("STRIPE_API_KEY", "sk"+"_live_"+strings.Repeat("Pp8Oo9", 5)); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.Get("STRIPE_API_KEY"); e.Exposed {
		t.Fatal("a new value did not lift the exposure")
	}
}

// A captured entry is unconfirmed: no sandbox gets it until the person
// confirms it (a sandbox can post a prompt-shaped call of its own) or
// replaces its value. An exposed entry cannot be confirmed.
func TestCapturedEntriesNeedConfirmation(t *testing.T) {
	s := newStore(t)
	if _, err := s.Capture(CaptureInput{Value: fakeGitHub(), Kind: "github-token", From: "claudecode prompt in sandbox sb"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Resolve("GITHUB_TOKEN"); !errors.Is(err, ErrUnconfirmed) || !strings.Contains(err.Error(), "vault confirm GITHUB_TOKEN") {
		t.Fatalf("resolve unconfirmed = %v", err)
	}
	if h, err := s.Hint("GITHUB_TOKEN"); err != nil || h != fakeGitHub()[len(fakeGitHub())-4:] {
		t.Fatalf("hint = %q %v", h, err)
	}
	if e, err := s.Confirm("GITHUB_TOKEN"); err != nil || e.Status() != StatusReady {
		t.Fatalf("confirm = %+v %v", e, err)
	}
	if _, v, err := s.Resolve("GITHUB_TOKEN"); err != nil || v != fakeGitHub() {
		t.Fatalf("resolve confirmed = %v", err)
	}
	if _, err := s.Capture(CaptureInput{Value: fakeStripe(), Kind: "stripe-secret-key", Exposed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm("STRIPE_API_KEY"); !errors.Is(err, ErrExposed) {
		t.Fatalf("confirm exposed = %v", err)
	}
	if _, err := s.ReplaceValue("STRIPE_API_KEY", "sk"+"_live_"+strings.Repeat("Rr3Ss4", 5)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Resolve("STRIPE_API_KEY"); err != nil {
		t.Fatalf("replaced entry = %v", err)
	}
}
