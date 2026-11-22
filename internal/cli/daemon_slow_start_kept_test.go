// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// GAP-2022: an interactive start or restart keeps a live gateway that is
// still starting at the readiness deadline instead of stopping it; a
// gateway that reports a fatal error is still stopped.
func TestWaitForStartedDaemonKeepsSlowLiveProcessForInteractiveStart(t *testing.T) {
	starting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled))
	}))
	defer starting.Close()

	process := &fakeReadinessProcess{running: true, pid: 42}
	_, ready, err := waitForStartedDaemon(process, 42, starting.Client(), starting.URL,
		25*time.Millisecond, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, keepSlowStart: true})
	if ready || !errors.Is(err, errGatewayStillStarting) || !strings.Contains(err.Error(), "remained STARTING") {
		t.Fatalf("ready = %v, error = %v, want still starting", ready, err)
	}
	if process.stopCalls != 0 {
		t.Fatalf("stop calls = %d, want the slow gateway left running", process.stopCalls)
	}
	msg := reportGatewayStillStarting(42, "/tmp/gateway.log", nil, errors.New("no config"), false).Error()
	// GAP-0478: say protection is not active yet, and keep the probe internals out.
	for _, want := range []string{"PID 42", "still starting and was left running", "Protection is not active",
		"defenseclaw-gateway status", "defenseclaw-gateway restart"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "remained STARTING") {
		t.Fatalf("message %q repeats the readiness probe detail", msg)
	}

	fatal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: gateway.StateError, LastError: "bind failed"},
		})
	}))
	defer fatal.Close()
	process = &fakeReadinessProcess{running: true, pid: 42}
	_, _, err = waitForStartedDaemon(process, 42, fatal.Client(), fatal.URL,
		25*time.Millisecond, 5*time.Millisecond, daemonReadinessRequirements{keepSlowStart: true})
	if err == nil || errors.Is(err, errGatewayStillStarting) || process.stopCalls != 1 {
		t.Fatalf("error = %v, stop calls = %d, want the failed gateway stopped", err, process.stopCalls)
	}
}

// GAP-1160: a gateway that is still starting when the readiness deadline ends
// is left running. A `start` that is a systemd unit's ExecStart (Type=forking,
// "defenseclaw-gateway start") exits 0 so the unit becomes active; a non-zero
// exit failed the unit, ExecStop stopped the gateway and Restart=on-failure
// looped. Every other caller, and `restart`, keeps the non-zero exit.
func TestReportGatewayStillStartingExitsZeroForAUnitStart(t *testing.T) {
	if err := reportGatewayStillStarting(42, "/tmp/gateway.log", nil, errors.New("no config"), true); err != nil {
		t.Fatalf("a unit's still-starting gateway must exit 0, got %v", err)
	}
	err := reportGatewayStillStarting(42, "/tmp/gateway.log", nil, errors.New("no config"), false)
	if err == nil || !strings.Contains(err.Error(), "still starting and was left running") {
		t.Fatalf("a start outside a unit (and every restart) must keep the non-zero exit, got %v", err)
	}
}

// The signal is "this process is the unit's ExecStart process", not "this
// process or an ancestor runs in a unit" (INVOCATION_ID is inherited by every
// child of a unit).
func TestUnitExecStartProcess(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	unit := "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name      string
		goos      string
		env       map[string]string
		pid, ppid int
		want      bool
	}{
		{"not under systemd", "linux", nil, 500, 400, false},
		{"unit child with a different exec pid", "linux", map[string]string{"INVOCATION_ID": unit, "SYSTEMD_EXEC_PID": "321"}, 500, 321, false},
		{"unit descendant, old systemd, parent is not init", "linux", map[string]string{"INVOCATION_ID": unit}, 500, 321, false},
		{"unit command, systemd 248+", "linux", map[string]string{"INVOCATION_ID": unit, "SYSTEMD_EXEC_PID": "500"}, 500, 321, true},
		{"unit command, older systemd, parent is init", "linux", map[string]string{"INVOCATION_ID": unit}, 500, 1, true},
		{"orphaned unit descendant keeps its stale exec pid", "linux", map[string]string{"INVOCATION_ID": unit, "SYSTEMD_EXEC_PID": "321"}, 500, 1, false},
		{"exec pid without an invocation", "linux", map[string]string{"SYSTEMD_EXEC_PID": "500"}, 500, 1, false},
		{"unparsable exec pid", "linux", map[string]string{"INVOCATION_ID": unit, "SYSTEMD_EXEC_PID": "x"}, 500, 1, false},
		{"macOS", "darwin", map[string]string{"INVOCATION_ID": unit, "SYSTEMD_EXEC_PID": "500"}, 500, 1, false},
		{"Windows", "windows", map[string]string{"INVOCATION_ID": unit, "SYSTEMD_EXEC_PID": "500"}, 500, 1, false},
	}
	for _, c := range cases {
		if got := unitExecStartProcess(c.goos, env(c.env), c.pid, c.ppid); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// A gateway that failed or exited is not "still starting": under a unit the
// start still fails, so systemd restarts it (the exit-0 path is only for a
// live gateway).
func TestUnitStartStillFailsForAFatalReadiness(t *testing.T) {
	t.Setenv("INVOCATION_ID", "0123456789abcdef0123456789abcdef")
	t.Setenv("SYSTEMD_EXEC_PID", strconv.Itoa(os.Getpid()))
	fatal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: gateway.StateError, LastError: "bind failed"},
		})
	}))
	defer fatal.Close()
	process := &fakeReadinessProcess{running: true, pid: 42}
	_, _, err := waitForStartedDaemon(process, 42, fatal.Client(), fatal.URL,
		25*time.Millisecond, 5*time.Millisecond, daemonReadinessRequirements{keepSlowStart: true})
	if err == nil || errors.Is(err, errGatewayStillStarting) || process.stopCalls != 1 {
		t.Fatalf("error = %v, stop calls = %d, want the failed gateway stopped and reported", err, process.stopCalls)
	}
	gone := &fakeReadinessProcess{running: false, pid: 42}
	_, _, err = waitForStartedDaemon(gone, 42, fatal.Client(), fatal.URL,
		25*time.Millisecond, 5*time.Millisecond, daemonReadinessRequirements{keepSlowStart: true})
	if err == nil || errors.Is(err, errGatewayStillStarting) {
		t.Fatalf("an exited gateway: error = %v, want a failure", err)
	}
}
