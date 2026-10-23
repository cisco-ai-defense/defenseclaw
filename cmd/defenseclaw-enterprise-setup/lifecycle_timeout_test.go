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
