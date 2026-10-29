// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const (
	lifecycleHelperMode    = "DC_SETUP_LIFECYCLE_HELPER"
	lifecycleHelperPIDFile = "DC_SETUP_LIFECYCLE_PIDFILE"
)

// TestEnterpriseLifecycleChildHelper is the lifecycle and recovery child the
// timeout tests start: this test binary, run again with a mode.
func TestEnterpriseLifecycleChildHelper(t *testing.T) {
	mode := os.Getenv(lifecycleHelperMode)
	if mode == "" {
		t.Skip("helper process only")
	}
	pidFile := os.Getenv(lifecycleHelperPIDFile)
	report := func(ok, pending bool, exit int, errs ...string) {
		messages := make([]map[string]string, 0, len(errs))
		for _, message := range errs {
			messages = append(messages, map[string]string{"code": "lifecycle_error", "message": message})
		}
		body, _ := json.Marshal(map[string]any{
			"schema_version": 2, "action": "recover", "profile": "standalone", "platform": "windows",
			"ok": ok, "exit_code": exit, "installed": true, "installed_version": "1.0.3",
			"transaction_pending": pending, "errors": messages,
			"services": []map[string]any{{"name": "DefenseClawGateway", "kind": "gateway", "state": "running", "required": true}},
		})
		fmt.Fprintln(os.Stdout, "recovery diagnostics before the result")
		os.Stdout.Write(append(body, '\n'))
		os.Exit(exit)
	}
	switch mode {
	case "hang":
		// The interrupted mutation: it would hold the transaction open.
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		time.Sleep(5 * time.Minute)
		os.Exit(0)
	case "recover":
		// The recovery replays the journal only once the stopped child is
		// gone; one still running would race it.
		pid, err := strconv.Atoi(strings.TrimSpace(readHelperFile(pidFile)))
		if err != nil || lifecycleHelperProcessAlive(pid) {
			report(false, true, 1, "the timed-out lifecycle child was still running during recovery")
		}
		report(true, false, 0)
	case "pending":
		report(true, true, 0)
	case "own-deadline", "own-failure":
		// The ensure child ended itself, at the deadline Setup handed it or
		// with another failure, and printed its result.
		code := "lifecycle_timeout"
		if mode == "own-failure" {
			code = "lifecycle_error"
		}
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		body, _ := json.Marshal(map[string]any{
			"schema_version": 2, "action": "ensure", "profile": "standalone", "platform": "windows",
			"ok": false, "exit_code": 1603, "installed": false,
			"errors": []map[string]string{{"code": code, "message": code + ": Windows enterprise installer did not finish"}},
		})
		os.Stdout.Write(append(body, byte(10)))
		os.Exit(1)
	case "refused":
		report(false, false, 1, "Setup replayed only the pending transaction, so the deployment is not reported settled: "+
			"these lifecycle records remain for the full recovery of an ensure run as LocalSystem: state-purge intent")
	}
	os.Exit(3)
}

func readHelperFile(path string) string {
	body, _ := os.ReadFile(path)
	return string(body)
}

func lifecycleHelperProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// FindProcess opens the process: it fails once the process is gone.
		_ = process.Release()
		return true
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// GAP-0501, executed: TIMEOUTSECONDS kills a real lifecycle child mid-run,
// and Setup then runs its one bounded recovery child, after the kill, before
// it returns; it reports only what that recovery proved.
func TestTimeoutKillsTheLifecycleChildThenRecoversBeforeReturning(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := func(mode, pidFile string, calls *int) func(context.Context) ([]byte, error) {
		return func(ctx context.Context) ([]byte, error) {
			if calls != nil {
				*calls++
			}
			child := processutil.CommandContext(ctx, executable, "-test.run=^TestEnterpriseLifecycleChildHelper$")
			child.Env = append(os.Environ(), lifecycleHelperMode+"="+mode, lifecycleHelperPIDFile+"="+pidFile)
			var captured bytes.Buffer
			child.Stdout = &captured
			err := processutil.RunTree(child)
			return captured.Bytes(), err
		}
	}
	previousLimit := enterpriseSetupRecoveryTimeout
	t.Cleanup(func() { enterpriseSetupRecoveryTimeout = previousLimit })
	cases := []struct {
		name, action, recovery string
		recoveryLimit          time.Duration
		recovered              bool
		recoveryRuns           int
		failure                string
	}{
		{name: "recovered", action: "ensure", recovery: "recover", recoveryLimit: time.Minute, recovered: true, recoveryRuns: 1},
		{name: "uninstall recovered", action: "uninstall", recovery: "recover", recoveryLimit: time.Minute, recovered: true, recoveryRuns: 1},
		{name: "still pending", action: "upgrade", recovery: "pending", recoveryLimit: time.Minute, recoveryRuns: 1, failure: "did not prove a settled deployment state"},
		{name: "other record left", action: "repair", recovery: "refused", recoveryLimit: time.Minute, recoveryRuns: 1, failure: "as LocalSystem: state-purge intent"},
		{name: "recovery hangs", action: "install", recovery: "hang", recoveryLimit: 2 * time.Second, recoveryRuns: 1, failure: "within 2s"},
		{name: "status is not recovered", action: "status", recovery: "recover", recoveryLimit: time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enterpriseSetupRecoveryTimeout = tc.recoveryLimit
			dir := t.TempDir()
			childPID := filepath.Join(dir, "child.pid")
			recoveryPID := childPID
			if tc.recovery == "hang" {
				recoveryPID = filepath.Join(dir, "recovery.pid")
			}
			opts := enterpriseSetupOptions{Action: tc.action, Standalone: true, JSON: true, LifecycleTimeout: 2 * time.Second}
			recoveries := 0
			started := time.Now()
			run := runEnterpriseLifecycleChild(context.Background(), opts,
				helper("hang", childPID, nil), helper(tc.recovery, recoveryPID, &recoveries))
			if elapsed := time.Since(started); elapsed > time.Minute {
				t.Fatalf("Setup returned after %s: the kill or the recovery bound did not hold", elapsed)
			}
			if !run.timedOut || !errors.Is(run.cause, context.DeadlineExceeded) || run.runErr == nil {
				t.Fatalf("child run timedOut=%v cause=%v err=%v", run.timedOut, run.cause, run.runErr)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(readHelperFile(childPID)))
			if pid == 0 || lifecycleHelperProcessAlive(pid) {
				t.Fatalf("the timed-out lifecycle child %d was not killed", pid)
			}
			if recoveries != tc.recoveryRuns {
				t.Fatalf("recovery ran %d times, want %d", recoveries, tc.recoveryRuns)
			}
			err := timedOutEnterpriseLifecycleError(opts, run)
			var timeout enterpriseSetupLifecycleTimeout
			if !errors.As(err, &timeout) {
				t.Fatalf("timeout error = %v", err)
			}
			if (run.recovery != nil) != tc.recovered || (timeout.recovery != nil) != tc.recovered {
				t.Fatalf("recovered=%v (%v), want %v", run.recovery != nil, run.recoveryErr, tc.recovered)
			}
			if tc.failure != "" {
				if run.recoveryErr == nil || !strings.Contains(err.Error(), tc.failure) ||
					!strings.Contains(err.Error(), "/ensure") {
					t.Fatalf("an unproven recovery must name why and the manual ensure: %v", err)
				}
			}
			if tc.recoveryRuns == 0 || !tc.recovered {
				return
			}
			var stdout, stderr bytes.Buffer
			writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName, opts, err, enterpriseFailureExitCode)
			var result struct {
				Action             string `json:"action"`
				OK                 bool   `json:"ok"`
				TransactionPending bool   `json:"transaction_pending"`
				Services           []struct {
					State string `json:"state"`
				} `json:"services"`
				Errors []struct {
					Code string `json:"code"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Action != tc.action || result.OK ||
				result.TransactionPending || len(result.Services) != 1 || result.Services[0].State != "running" ||
				len(result.Errors) != 1 || result.Errors[0].Code != "lifecycle_timeout" {
				t.Fatalf("Setup result after a recovered timeout = %s (%v)", stdout.String(), err)
			}
		})
	}
}

// GAP-2456: the standalone ensure child ends itself at the deadline Setup
// hands it (GAP-2265), shortly before TIMEOUTSECONDS, so Setup limit never
// fires. That stop can land after the transaction commits and before the
// scanner runtime step, so it gets the same bounded recovery as a stop by
// Setup itself; any other child failure, and a read-only action, do not.
func TestAChildThatEndedAtItsOwnDeadlineIsRecoveredLikeATimeout(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := func(mode, pidFile string, calls *int) func(context.Context) ([]byte, error) {
		return func(ctx context.Context) ([]byte, error) {
			if calls != nil {
				*calls++
			}
			child := processutil.CommandContext(ctx, executable, "-test.run=^TestEnterpriseLifecycleChildHelper$")
			child.Env = append(os.Environ(), lifecycleHelperMode+"="+mode, lifecycleHelperPIDFile+"="+pidFile)
			var captured bytes.Buffer
			child.Stdout = &captured
			err := processutil.RunTree(child)
			return captured.Bytes(), err
		}
	}
	cases := []struct {
		name, action, mode string
		recovered          bool
	}{
		{name: "ensure ended at its own deadline", action: "ensure", mode: "own-deadline", recovered: true},
		{name: "ensure failed otherwise", action: "ensure", mode: "own-failure"},
		{name: "status is not recovered", action: "status", mode: "own-deadline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			childPID := filepath.Join(t.TempDir(), "child.pid")
			opts := enterpriseSetupOptions{Action: tc.action, Standalone: true, JSON: true, LifecycleTimeout: time.Minute}
			recoveries := 0
			run := runEnterpriseLifecycleChild(context.Background(), opts,
				helper(tc.mode, childPID, nil), helper("recover", childPID, &recoveries))
			if run.runErr == nil {
				t.Fatal("the child failure was lost")
			}
			if !tc.recovered {
				if run.timedOut || recoveries != 0 || run.recovery != nil {
					t.Fatalf("timedOut=%v recoveries=%d: only a stop at the deadline is recovered", run.timedOut, recoveries)
				}
				return
			}
			if !run.timedOut || !errors.Is(run.cause, context.DeadlineExceeded) || recoveries != 1 || run.recovery == nil {
				t.Fatalf("timedOut=%v cause=%v recoveries=%d recovery=%v (%v): a child that ended at its own deadline was not recovered",
					run.timedOut, run.cause, recoveries, run.recovery != nil, run.recoveryErr)
			}
			err := timedOutEnterpriseLifecycleError(opts, run)
			if err == nil || !strings.Contains(err.Error(), "Setup replayed its pending transaction") {
				t.Fatalf("timeout error = %v", err)
			}
			var stdout, stderr bytes.Buffer
			writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName, opts, err, enterpriseFailureExitCode)
			var result struct {
				Installed bool `json:"installed"`
				Errors    []struct {
					Code string `json:"code"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || !result.Installed ||
				len(result.Errors) != 1 || result.Errors[0].Code != "lifecycle_timeout" {
				t.Fatalf("Setup result = %s (%v)", stdout.String(), err)
			}
		})
	}
}

// The recovery child repeats none of the interrupted request's switches.
func TestStandaloneRecoveryOptionsDropTheRequestOnlySwitches(t *testing.T) {
	got := standaloneRecoveryOptions(enterpriseSetupOptions{
		Action: "uninstall", Standalone: true, Force: true, Purge: true, NoStart: true,
		AttestAgentApplicationControl: true, AttestClaudeEffectivePolicy: true, LifecycleTimeout: time.Minute,
	})
	want := enterpriseSetupOptions{Action: "recover", Standalone: true, JSON: true, LifecycleTimeout: time.Minute}
	if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", want) {
		t.Fatalf("recovery options = %+v", got)
	}
}

// GAP-2509: a standalone Setup's TIMEOUTSECONDS counts from Setup's start,
// so the payload checks and unpacking before the lifecycle child count. On
// a loaded host they took minutes and Setup ran past TIMEOUTSECONDS plus its
// recovery bound. A run whose limit is used up before the child starts does
// not start it, recovers nothing and says nothing changed; a run without a
// start time (Secure Client, the recovery watchdog) keeps the full limit.
func TestTimeoutSecondsCountsFromSetupStart(t *testing.T) {
	limit := 10 * time.Minute
	now := time.Now()
	opts := enterpriseSetupOptions{
		Action: "ensure", Standalone: true, Config: `C:\cfg\config.yaml`,
		LifecycleTimeout: limit, Started: now.Add(-4 * time.Minute),
	}
	if got, want := enterpriseSetupLifecycleDeadline(opts, now), opts.Started.Add(limit); !got.Equal(want) {
		t.Fatalf("deadline = %s, want Started + TIMEOUTSECONDS = %s", got, want)
	}
	var deadline time.Time
	run := runEnterpriseLifecycleChild(context.Background(), opts, func(ctx context.Context) ([]byte, error) {
		deadline, _ = ctx.Deadline()
		return nil, nil
	}, func(context.Context) ([]byte, error) {
		t.Fatal("recovery ran for a child that finished")
		return nil, nil
	})
	if run.timedOut || run.notStarted {
		t.Fatalf("run = %+v, want a finished child", run)
	}
	if spent := deadline.Sub(opts.Started); spent > limit+time.Second {
		t.Fatalf("child deadline is %s after Setup's start, want at most TIMEOUTSECONDS (%s)", spent, limit)
	}

	opts.Started = now.Add(-limit - time.Minute)
	started, recovered := false, false
	run = runEnterpriseLifecycleChild(context.Background(), opts, func(context.Context) ([]byte, error) {
		started = true
		return nil, nil
	}, func(context.Context) ([]byte, error) {
		recovered = true
		return nil, nil
	})
	if started || recovered || !run.timedOut || !run.notStarted || !errors.Is(run.cause, context.DeadlineExceeded) {
		t.Fatalf("used-up limit: started=%t recovered=%t run=%+v, want the child not started and no recovery", started, recovered, run)
	}
	err := timedOutEnterpriseLifecycleError(opts, run)
	var timeout enterpriseSetupLifecycleTimeout
	if !errors.As(err, &timeout) || timeout.recovery != nil ||
		!strings.Contains(err.Error(), "did not start within TIMEOUTSECONDS=600") ||
		!strings.Contains(err.Error(), "nothing was changed") ||
		!strings.Contains(err.Error(), "TIMEOUTSECONDS=7200") {
		t.Fatalf("used-up limit error = %v, want the not-started timeout with the retry", err)
	}

	opts.Started = time.Time{}
	if got := enterpriseSetupLifecycleDeadline(opts, now); !got.Equal(now.Add(limit)) {
		t.Fatalf("no start time: deadline = %s, want now + TIMEOUTSECONDS", got)
	}
	if started := enterpriseSetupProcessStarted(); started.IsZero() || started.After(time.Now()) {
		t.Fatalf("process start = %s, want a time not after now", started)
	}
}

// GAP-2509 review: a run that counts from Setup's start does not start a
// lifecycle child with too little of TIMEOUTSECONDS left. The ensure child
// accepts no deadline under 60 seconds, so with under about 67 seconds left
// it was handed 60 while Setup's own deadline came first: Setup stopped the
// child tree mid-transaction (the GAP-2265 shape) and left the result to its
// recovery. Such a run now changes nothing and prints the retry.
func TestALifecycleWithTooLittleOfTheLimitLeftDoesNotStart(t *testing.T) {
	limit := 2 * time.Minute
	cases := []struct {
		action    string
		left      time.Duration
		wantStart bool
	}{
		{"ensure", 30 * time.Second, false},
		{"ensure", 62 * time.Second, false},
		{"ensure", 75 * time.Second, true},
		{"upgrade", 30 * time.Second, false},
		{"upgrade", 70 * time.Second, true},
		{"uninstall", 30 * time.Second, false},
		{"status", 10 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s-%s", tc.action, tc.left), func(t *testing.T) {
			opts := enterpriseSetupOptions{
				Action: tc.action, Standalone: true, Config: `C:\cfg\config.yaml`,
				LifecycleTimeout: limit, Started: time.Now().Add(tc.left - limit),
			}
			started, recovered := false, false
			var deadline time.Time
			run := runEnterpriseLifecycleChild(context.Background(), opts, func(ctx context.Context) ([]byte, error) {
				started = true
				deadline, _ = ctx.Deadline()
				return nil, nil
			}, func(context.Context) ([]byte, error) {
				recovered = true
				return nil, nil
			})
			if started != tc.wantStart || recovered || run.notStarted == tc.wantStart {
				t.Fatalf("started=%t recovered=%t run=%+v, want started=%t and no recovery", started, recovered, run, tc.wantStart)
			}
			if !tc.wantStart {
				err := timedOutEnterpriseLifecycleError(opts, run)
				if !errors.Is(run.cause, context.DeadlineExceeded) ||
					!strings.Contains(err.Error(), "did not start within TIMEOUTSECONDS=120") ||
					!strings.Contains(err.Error(), "nothing was changed") {
					t.Fatalf("too-late error = %v, want the not-started timeout", err)
				}
				return
			}
			if tc.action == "ensure" {
				seconds := enterpriseEnsureChildTimeoutSeconds(time.Until(deadline) + time.Second)
				if child := time.Now().Add(time.Duration(seconds) * time.Second); !child.Before(deadline) {
					t.Fatalf("ensure child deadline %s is not before Setup's %s", child, deadline)
				}
			}
		})
	}

	// Without a start time (no Setup start known) the child keeps its
	// 60-second minimum, as before.
	if got := enterpriseEnsureChildTimeoutSeconds(30 * time.Second); got != 60 {
		t.Fatalf("no start time: child seconds = %d, want the 60-second minimum", got)
	}
	if got := enterpriseEnsureChildTimeoutSeconds(30 * time.Minute); got != 28*60 {
		t.Fatalf("default limit: child seconds = %d, want 1680", got)
	}
	opts := enterpriseSetupOptions{Action: "ensure", Standalone: true, LifecycleTimeout: time.Minute}
	if enterpriseLifecycleChildTooLate(opts, 30*time.Second) {
		t.Fatal("a run without a start time was refused")
	}
}

// GAP-2509 review (P4): Setup's start time is on the process's monotonic
// clock, so a wall-clock step after the start does not move the deadline.
func TestSetupStartTimeIsOnTheMonotonicClock(t *testing.T) {
	now := time.Now()
	creation := now.Add(-90 * time.Second).Round(0)
	started := enterpriseSetupStartFromCreation(now, creation)
	if !started.Equal(creation) {
		t.Fatalf("start = %s, want the creation time %s", started, creation)
	}
	if !strings.Contains(started.String(), "m=") {
		t.Fatalf("start %s has no monotonic reading", started.String())
	}
	if got := enterpriseSetupStartFromCreation(now, now.Add(time.Minute)); !got.IsZero() {
		t.Fatalf("future creation: start = %s, want zero", got)
	}
	if got := enterpriseSetupStartFromCreation(now, time.Unix(0, 0)); !got.IsZero() {
		t.Fatalf("unset creation: start = %s, want zero", got)
	}
}
