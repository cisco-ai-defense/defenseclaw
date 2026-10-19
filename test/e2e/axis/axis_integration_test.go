//go:build axis_integration

// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const researchedCommit = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
const researchedVersion = "axis 0.3.5"

func (s *probeSession) preflight(pin runtimePin) error {
	if err := requireLinux(runtime.GOOS); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("AXIS feasibility must run under a disposable unprivileged account")
	}
	return verifyRuntime(pin)
}

var axisPath = flag.String("axis-path", "", "absolute local AXIS executable reviewed for the feasibility source pin")
var axisSHA256 = flag.String("axis-sha256", "", "independently reviewed SHA256 of that AXIS executable (64 hex digits)")

func liveSession(t *testing.T) (*probeSession, runtimePin) {
	t.Helper()
	if err := requireLinux(runtime.GOOS); err != nil {
		t.Fatal(err)
	}
	pin := runtimePin{*axisPath, *axisSHA256}
	// The build tag opts into a live test. Missing flags are failures, not a
	// successful skip that could be mistaken for Linux runtime evidence.
	if err := verifyRuntime(pin); err != nil {
		t.Fatal(err)
	}
	s, err := newProbeSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Errorf("remove owned probe files: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := s.version(ctx, pin)
	if err != nil || result.exitCode != 0 || result.timedOut || result.truncated || strings.TrimSpace(result.stdout) != researchedVersion {
		t.Fatalf("reviewed AXIS version check failed (exit=%d, timeout=%t, error=%v); diagnostics withheld", result.exitCode, result.timedOut, err)
	}
	t.Logf("offline feasibility only: source=%s sha256=%s version=%q host=%s/%s", researchedCommit, pin.sha256, researchedVersion, runtime.GOOS, runtime.GOARCH)
	return s, pin
}

func TestLiveAXISOfflineLifecycle(t *testing.T) {
	s, pin := liveSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// This fixed benign payload never prints the environment or contacts a
	// service. Parameters are separate argv entries, not shell interpolation.
	const script = `set -eu
[ "$HOME" = "$1" ]
[ "$PWD" = "$2" ]
[ "$TMPDIR" = "$3" ]
[ -z "${ANTHROPIC_API_KEY+x}" ]
[ -z "${CLAUDE_CODE_OAUTH_TOKEN+x}" ]
[ -z "${HTTP_PROXY+x}" ]
printf 'workspace-probe\n' > axis-probe.txt
printf 'private-state\n' > "$HOME/probe-state"
printf 'AXIS_OFFLINE_PROBE_OK\n'
exit 23`
	result, err := s.run(ctx, pin, "/bin/sh", "-c", script, "axis-offline-probe", s.home, s.workspace, s.temporary)
	if err != nil || result.exitCode != 23 || result.timedOut || result.truncated || !strings.Contains(result.stdout, "AXIS_OFFLINE_PROBE_OK") {
		t.Fatalf("offline lifecycle failed (exit=%d, timeout=%t, truncated=%t, error=%v); diagnostics withheld", result.exitCode, result.timedOut, result.truncated, err)
	}
	for path, want := range map[string]string{
		filepath.Join(s.workspace, "axis-probe.txt"): "workspace-probe\n",
		filepath.Join(s.home, "probe-state"):         "private-state\n",
	} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("private probe file differs: %v", err)
		}
	}
	t.Log("observed headless child exit 23 and writes in owned HOME/workspace; no Claude or security certification")
}

func TestLiveAXISOfflineTimeout(t *testing.T) {
	s, pin := liveSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := s.run(ctx, pin, "/bin/sh", "-c", "printf AXIS_OFFLINE_WAITING; exec /bin/sleep 60")
	if err != nil || !result.timedOut || !strings.Contains(result.stdout, "AXIS_OFFLINE_WAITING") {
		t.Fatalf("offline timeout failed (exit=%d, timeout=%t, error=%v); diagnostics withheld", result.exitCode, result.timedOut, err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.root); !os.IsNotExist(err) {
		t.Fatal("owned temporary probe files survived cleanup")
	}
	t.Log("observed bounded timeout and owned-file cleanup; escaped descendants and AXIS runtime-object cleanup remain unqualified")
}
