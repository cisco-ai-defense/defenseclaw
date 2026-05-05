// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// promptHelperSpawnTracker is a tiny fixture for the spawn callback.
// We use a struct (rather than a free closure) so each test sees a
// fresh “called“ count without bleeding state from a sibling test —
// table-driven tests share package-level state by default and that
// has bitten this codebase before.
type promptHelperSpawnTracker struct {
	called int
	err    error
}

func (s *promptHelperSpawnTracker) spawn() error {
	s.called++
	return s.err
}

// TestPromptFirstRunBeforeTUI_SkipFlagShortCircuits locks in the
// contract that “--skip-first-run-prompt“ is honoured even when
// stdin is a real TTY and an answer is sitting in the buffer. We
// assert the helper does NOT consume stdin in this case so an
// upstream caller can keep using it for whatever else they had
// queued up.
func TestPromptFirstRunBeforeTUI_SkipFlagShortCircuits(t *testing.T) {
	in := strings.NewReader("y\n")
	out := &bytes.Buffer{}
	tracker := &promptHelperSpawnTracker{}

	outcome, err := promptFirstRunBeforeTUI(in, out, true, true, tracker.spawn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != firstRunUnavailable {
		t.Errorf("outcome=%v, want firstRunUnavailable", outcome)
	}
	if tracker.called != 0 {
		t.Errorf("spawn called %d times, want 0 when skip=true", tracker.called)
	}
	if out.Len() != 0 {
		t.Errorf("out should be empty when skip=true, got %q", out.String())
	}
	// The "y\n" must remain unread so callers can do something
	// useful with it. Reading remaining bytes verifies that.
	rest, _ := readAll(in)
	if rest != "y\n" {
		t.Errorf("stdin should not be consumed, got remaining %q", rest)
	}
}

// TestPromptFirstRunBeforeTUI_NonTTYShortCircuits ensures that
// pipe/file stdin (CI, scripts) never hits the wizard, which would
// hang waiting for input that nobody is going to provide.
func TestPromptFirstRunBeforeTUI_NonTTYShortCircuits(t *testing.T) {
	in := strings.NewReader("y\n")
	out := &bytes.Buffer{}
	tracker := &promptHelperSpawnTracker{}

	outcome, err := promptFirstRunBeforeTUI(in, out, false, false, tracker.spawn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != firstRunUnavailable {
		t.Errorf("outcome=%v, want firstRunUnavailable", outcome)
	}
	if tracker.called != 0 {
		t.Errorf("spawn called %d times, want 0 when ttyOK=false", tracker.called)
	}
}

// TestPromptFirstRunBeforeTUI_EmptyAnswerDefaultsToYes guards the
// UX contract that pressing Enter at the prompt accepts the default
// ([Y/n]) and runs the wizard. Regression check: an earlier draft
// treated empty as "skip", which silently downgraded first-time
// installs to the abbreviated embedded panel.
func TestPromptFirstRunBeforeTUI_EmptyAnswerDefaultsToYes(t *testing.T) {
	in := strings.NewReader("\n")
	out := &bytes.Buffer{}
	tracker := &promptHelperSpawnTracker{}

	outcome, err := promptFirstRunBeforeTUI(in, out, false, true, tracker.spawn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != firstRunHanded {
		t.Errorf("outcome=%v, want firstRunHanded for empty answer", outcome)
	}
	if tracker.called != 1 {
		t.Errorf("spawn called %d times, want 1", tracker.called)
	}
	if !strings.Contains(out.String(), "Run the setup wizard now? [Y/n]") {
		t.Errorf("missing prompt text in output:\n%s", out.String())
	}
}

// TestPromptFirstRunBeforeTUI_YesAccepts covers the explicit "y"
// path. We also accept "Y", "yes", "YES" — exercise mixed case so
// the lowercasing path doesn't regress.
func TestPromptFirstRunBeforeTUI_YesAccepts(t *testing.T) {
	for _, ans := range []string{"y\n", "Y\n", "yes\n", "YES\n", " yes \n"} {
		t.Run(strings.TrimSpace(ans), func(t *testing.T) {
			in := strings.NewReader(ans)
			out := &bytes.Buffer{}
			tracker := &promptHelperSpawnTracker{}

			outcome, err := promptFirstRunBeforeTUI(in, out, false, true, tracker.spawn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if outcome != firstRunHanded {
				t.Errorf("outcome=%v, want firstRunHanded", outcome)
			}
			if tracker.called != 1 {
				t.Errorf("spawn called %d times, want 1", tracker.called)
			}
		})
	}
}

// TestPromptFirstRunBeforeTUI_NoDeclines covers the "n" / "no" /
// "NO" path. Spawn must NOT be called, and the outcome is
// “firstRunDeclined“ (NOT “firstRunUnavailable“) so the caller
// can suppress the embedded first-run panel — operators who said
// "n" don't want it back five seconds later.
func TestPromptFirstRunBeforeTUI_NoDeclines(t *testing.T) {
	for _, ans := range []string{"n\n", "N\n", "no\n", "NO\n"} {
		t.Run(strings.TrimSpace(ans), func(t *testing.T) {
			in := strings.NewReader(ans)
			out := &bytes.Buffer{}
			tracker := &promptHelperSpawnTracker{}

			outcome, err := promptFirstRunBeforeTUI(in, out, false, true, tracker.spawn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if outcome != firstRunDeclined {
				t.Errorf("outcome=%v, want firstRunDeclined", outcome)
			}
			if tracker.called != 0 {
				t.Errorf("spawn called %d times, want 0", tracker.called)
			}
			if !strings.Contains(out.String(), "defenseclaw init") {
				t.Errorf("decline message should hint at `defenseclaw init`, got:\n%s", out.String())
			}
		})
	}
}

// TestPromptFirstRunBeforeTUI_GibberishUnavailable ensures we don't
// silently treat an unparseable answer as "yes". The operator gets
// a helpful message and we degrade to “firstRunUnavailable“ so the
// embedded panel can take over (rather than “firstRunDeclined“,
// which would suppress everything and drop them into a blank TUI).
func TestPromptFirstRunBeforeTUI_GibberishUnavailable(t *testing.T) {
	in := strings.NewReader("maybe\n")
	out := &bytes.Buffer{}
	tracker := &promptHelperSpawnTracker{}

	outcome, err := promptFirstRunBeforeTUI(in, out, false, true, tracker.spawn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != firstRunUnavailable {
		t.Errorf("outcome=%v, want firstRunUnavailable for gibberish", outcome)
	}
	if tracker.called != 0 {
		t.Errorf("spawn called %d times, want 0", tracker.called)
	}
	if !strings.Contains(out.String(), `"maybe"`) {
		t.Errorf("error message should quote the unparseable answer, got:\n%s", out.String())
	}
}

// TestPromptFirstRunBeforeTUI_SpawnFailureSurfaces guards against a
// silent-failure regression: a non-zero exit from the wizard MUST
// be reported back so the caller can warn the operator. We also
// confirm the outcome is “firstRunUnavailable“ (not
// “firstRunHanded“) so callers don't try to re-load a config that
// the failed wizard never wrote.
func TestPromptFirstRunBeforeTUI_SpawnFailureSurfaces(t *testing.T) {
	in := strings.NewReader("y\n")
	out := &bytes.Buffer{}
	tracker := &promptHelperSpawnTracker{err: errors.New("exit status 1")}

	outcome, err := promptFirstRunBeforeTUI(in, out, false, true, tracker.spawn)
	if err == nil {
		t.Fatal("expected error from failed spawn, got nil")
	}
	if !strings.Contains(err.Error(), "defenseclaw init") {
		t.Errorf("error should mention `defenseclaw init`, got %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("error should wrap the spawn error, got %v", err)
	}
	if outcome != firstRunUnavailable {
		t.Errorf("outcome=%v, want firstRunUnavailable on spawn failure", outcome)
	}
	if tracker.called != 1 {
		t.Errorf("spawn called %d times, want 1", tracker.called)
	}
}

// TestPromptFirstRunBeforeTUI_PromptIncludesFailModeAndHITL is the
// canary that makes sure the prompt actually mentions the two
// options that justify routing first-run through the CLI wizard
// (and NOT the embedded panel that doesn't surface them). If
// somebody trims the prompt text, this test fails immediately.
func TestPromptFirstRunBeforeTUI_PromptIncludesFailModeAndHITL(t *testing.T) {
	in := strings.NewReader("n\n")
	out := &bytes.Buffer{}
	tracker := &promptHelperSpawnTracker{}

	if _, err := promptFirstRunBeforeTUI(in, out, false, true, tracker.spawn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := out.String()
	for _, want := range []string{"connector", "profile", "fail-mode", "Human-In-the-Loop"} {
		if !strings.Contains(body, want) {
			t.Errorf("prompt should mention %q, got:\n%s", want, body)
		}
	}
}

// TestResolveDefenseclawBinForFirstRun_FallbackToLiteral exercises
// the last-resort branch: even on a stripped-down test runner with
// no “defenseclaw“ on PATH and an “os.Executable“ that resolves
// to a Go test binary (“cli.test“), the helper must always return
// a non-empty string. The fallback is the literal name so
// “exec.Cmd“ surfaces a useful "executable not found" error
// instead of trying to run the empty string (which yields a
// confusing "fork/exec : no such file or directory" message).
func TestResolveDefenseclawBinForFirstRun_FallbackToLiteral(t *testing.T) {
	got := resolveDefenseclawBinForFirstRun()
	if got == "" {
		t.Fatal("resolver must never return empty string")
	}
}

// readAll reads everything left in r into a string. Local helper to
// avoid pulling in io/ioutil for a single call.
func readAll(r interface{ Read(p []byte) (int, error) }) (string, error) {
	var b strings.Builder
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
		}
		if err != nil {
			if err.Error() == "EOF" {
				return b.String(), nil
			}
			return b.String(), err
		}
	}
}
