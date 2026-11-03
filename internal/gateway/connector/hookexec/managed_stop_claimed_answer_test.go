// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// claimedStopWriter records what the agent got from the watchdog and says
// when the watchdog wrote its answer (stdout is written last).
type claimedStopWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	once  sync.Once
	wrote chan struct{}
}

func newClaimedStopWriter() *claimedStopWriter { return &claimedStopWriter{wrote: make(chan struct{})} }

func (w *claimedStopWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	w.once.Do(func() { close(w.wrote) })
	return n, err
}

func (w *claimedStopWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// fakeStoppedSCM is the service manager of a stopped DefenseClawGateway
// (SERVICE_STOPPED, pid 0) as the managed transport reports it: a
// peer-verification failure that proves the service is not running
// (stoppedManagedGatewayError).
func fakeStoppedSCM() error {
	return fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, fakeStoppedServiceStatus())
}

// fakeStoppedServiceStatus is the service query's answer for SERVICE_STOPPED
// (state 1) with no process (queryManagedGatewayServicePID).
func fakeStoppedServiceStatus() error {
	return fmt.Errorf("%w (state=1 pid=0)", errManagedGatewayNotRunning)
}

// managedStoppedForms are the managed tool-call hooks of GAP-0294 (Claude Code
// and Codex, the same second) in the Windows standalone shape (SCM service)
// and the Unix standalone shape.
var managedStoppedForms = []struct {
	name      string
	connector string
	shape     func(*Options)
}{
	{"claudecode/windows", "claudecode", func(o *Options) {
		o.ExplainUnenrolledAccount = true
		o.ManagedGatewayServiceName = "DefenseClawGateway"
	}},
	{"codex/windows", "codex", func(o *Options) {
		o.ExplainUnenrolledAccount = true
		o.ManagedGatewayServiceName = "DefenseClawGateway"
	}},
	{"claudecode/unix", "claudecode", func(o *Options) { o.ManagedStandalone = true }},
	{"codex/unix", "codex", func(o *Options) { o.ManagedStandalone = true }},
}

func managedStoppedOptions(t *testing.T, connector string, shape func(*Options), stdout, stderr *claimedStopWriter, exit func(int)) Options {
	t.Helper()
	opts := Options{
		Connector:         connector,
		Event:             "PreToolUse",
		ManagedEnterprise: true,
		FailMode:          "closed",
		StartedAt:         time.Now(),
		Stdin:             strings.NewReader(""),
		Stdout:            stdout,
		Stderr:            stderr,
		Exit:              exit,
	}
	shape(&opts)
	return withDefaults(opts)
}

// failStoppedService is the managed transport's failure of a call whose
// service read proved the gateway stopped (hookexec.go, the
// errManagedGatewayPeerUnverified branch).
func failStoppedService(opts Options, sp spec, scmErr error) int {
	return failUnreachable(withManagedOutage(opts, scmErr), sp, managedPeerFailMode(opts, "closed", scmErr),
		managedPeerFailureReason(opts, scmErr))
}

func withoutRowRecordLine(stderr string) string {
	var kept []string
	for _, line := range strings.SplitAfter(stderr, "\n") {
		if !strings.HasPrefix(line, "defenseclaw: event_id=") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}

type claimedStopRow struct {
	Reason  string `json:"reason"`
	Outcome string `json:"outcome"`
}

func claimedStopRows(t *testing.T, home string) []claimedStopRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatalf("hook-failures.jsonl: %v", err)
	}
	var rows []claimedStopRow
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var row claimedStopRow
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		rows = append(rows, row)
	}
	return rows
}

// TestManagedStopProvenLateNamesNotRunningInAnswerAndRow pins rel-1-0-6
// GAP-0294: with DefenseClawGateway stopped on a loaded host the service read
// proves the stop only after the restart wait, close to the answer deadline.
// The call claims its hook-failures row (enterprise_managed_gateway_not_running)
// and the deadline passes while the row is written, before the call's own
// answer is out. The watchdog's answer is then the call's own: the
// not-running text and code, never the no-answer text, and it equals byte
// for byte the answer the call renders itself. The deadline is driven by
// hand from inside the row write; nothing sleeps.
func TestManagedStopProvenLateNamesNotRunningInAnswerAndRow(t *testing.T) {
	stubManagedLifecycle(t, func() bool { return false })
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute // a bound only: the row is released below
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })

	for _, form := range managedStoppedForms {
		t.Run(form.name, func(t *testing.T) {
			assertLateStopAnswer(t, form.connector, form.shape, fakeStoppedSCM)
		})
	}
}

// assertLateStopAnswer runs one GAP-0294 call of form: readSCM is the
// service read that proves the stop, the deadline passes while the call's
// row is written, and the watchdog's answer must be the call's own.
func assertLateStopAnswer(t *testing.T, connector string, shape func(*Options), readSCM func() error) {
	t.Helper()
	sp, ok := specFor(connector)
	if !ok {
		t.Fatalf("no spec for %s", connector)
	}
	home := t.TempDir()
	stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
	exited := make(chan int, 1)
	opts := managedStoppedOptions(t, connector, shape, stdout, stderr, func(code int) { exited <- code })
	w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})

	// The SCM read is late: by the time it proves the stop, the answer
	// deadline is due. It passes while the call's row is written (the
	// row's account lookup), after the call claimed it.
	var fired sync.Once
	opts.FailureLogHome = func() string {
		fired.Do(func() {
			go w.watch(time.Now())
			<-stdout.wrote
		})
		return home
	}
	code := failStoppedService(opts, sp, readSCM())

	var given int
	select {
	case given = <-exited:
	case <-time.After(time.Minute):
		t.Fatal("the watchdog never answered")
	}
	shown := stderr.String() + stdout.String()
	if !strings.Contains(shown, "("+managedGatewayNotRunningReason+")") || strings.Contains(shown, managedGatewayNoAnswerReason) {
		t.Fatalf("watchdog answer %q, want the %s text and no %s", shown, managedGatewayNotRunningReason, managedGatewayNoAnswerReason)
	}
	// The call's own answer also names its row's event id, a line the
	// row write prints (logHookFailure); the rest is the same.
	own := withoutRowRecordLine(w.err.String()) + w.out.String()
	if shown != own || given != code {
		t.Fatalf("watchdog answer %q exit %d, want the call's own answer %q exit %d", shown, given, own, code)
	}
	rows := claimedStopRows(t, home)
	if len(rows) != 1 || rows[0].Reason != managedGatewayNotRunningReason || rows[0].Outcome != "fail_closed" {
		t.Fatalf("rows %+v, want one fail_closed %s row", rows, managedGatewayNotRunningReason)
	}
}

// TestManagedStopProvenAfterTheDeadlineKeepsTheNoAnswerRow is the other side
// of the same decision: a service read still running when the deadline
// passes proves nothing in time. The watchdog answers no-answer and writes
// the no-answer row; the late read writes no second row.
func TestManagedStopProvenAfterTheDeadlineKeepsTheNoAnswerRow(t *testing.T) {
	stubManagedLifecycle(t, func() bool { return false })
	for _, form := range managedStoppedForms {
		t.Run(form.name, func(t *testing.T) {
			sp, _ := specFor(form.connector)
			home := t.TempDir()
			stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
			exited := make(chan int, 1)
			opts := managedStoppedOptions(t, form.connector, form.shape, stdout, stderr, func(code int) { exited <- code })
			opts.FailureLogHome = func() string { return home }
			w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
			go w.watch(time.Now())
			select {
			case <-exited:
			case <-time.After(time.Minute):
				t.Fatal("the watchdog never answered")
			}
			_ = failStoppedService(opts, sp, fakeStoppedSCM())
			shown := stderr.String() + stdout.String()
			if !strings.Contains(shown, managedGatewayNoAnswerReason) || strings.Contains(shown, managedGatewayNotRunningReason) {
				t.Fatalf("watchdog answer %q, want the %s text", shown, managedGatewayNoAnswerReason)
			}
			rows := claimedStopRows(t, home)
			if len(rows) != 1 || rows[0].Reason != managedGatewayNoAnswerReason {
				t.Fatalf("rows %+v, want one %s row", rows, managedGatewayNoAnswerReason)
			}
		})
	}
}

// TestClaimedFailureAnswerIsNotReplaced: once the call's row is claimed, the
// renders that come later (Run's adopt, an answered error) do not replace its
// answer with the no-answer text, and a closed claim of another reason keeps it.
func TestClaimedFailureAnswerIsNotReplaced(t *testing.T) {
	stubManagedLifecycle(t, func() bool { return false })
	sp, _ := specFor("claudecode")
	stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
	opts := managedStoppedOptions(t, "claudecode", managedStoppedForms[0].shape, stdout, stderr, nil)
	w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
	done, claimed := w.claimFailureLog(opts, sp, true, managedGatewayNotRunningReason, "closed", true)
	if !claimed {
		t.Fatal("first claim not taken")
	}
	close(done)
	want := string(w.fallbackErr) + string(w.fallbackOut)
	if !strings.Contains(want, managedGatewayNotRunningReason) {
		t.Fatalf("claimed answer %q, want the %s text", want, managedGatewayNotRunningReason)
	}
	w.adopt(&opts, sp, "closed")
	w.closeForAnsweredError(opts, sp)
	w.gatewayAnsweredError(opts, sp, 500)
	if _, again := w.claimFailureLog(opts, sp, true, "gateway unreachable", "closed", false); again {
		t.Fatal("second claim taken")
	}
	if got := string(w.fallbackErr) + string(w.fallbackOut); got != want || !w.closedKnown {
		t.Fatalf("answer after later renders %q (closed %v), want %q", got, w.closedKnown, want)
	}
	if !errors.Is(fakeStoppedSCM(), errManagedGatewayNotRunning) {
		t.Fatal("fake SCM does not prove the stop")
	}
}
