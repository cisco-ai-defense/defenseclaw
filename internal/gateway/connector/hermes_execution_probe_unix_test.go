// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestHermesRegistrationRequiresExecutableProbe(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	opts := SetupOpts{DataDir: filepath.Join(root, "dc")}
	script := filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'defenseclaw-execution-probe-ok\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(configPath, script, ""); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesAllowlist(filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName),
		hermesConfiguredHookCommand(script, ""), script); err != nil {
		t.Fatal(err)
	}
	conn := NewHermesConnector()
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("executable registration present=%v err=%v", present, err)
	}
	if err := os.Chmod(script, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("non-executable registration present=%v err=%v, want absent", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("early success without runtime proof present=%v err=%v, want absent", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("failed execution probe present=%v err=%v, want absent", present, err)
	}
}

func writeHermesProbeScript(t *testing.T, body string) string {
	t.Helper()
	script := filepath.Join(testenv.PrivateTempDir(t), "hermes-hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

func setHermesExecutionProbeBounds(t *testing.T, timeout, pipeWait time.Duration) {
	t.Helper()
	previousTimeout, previousPipeWait := hermesExecutionProbeTimeout, hermesExecutionProbePipeWait
	hermesExecutionProbeTimeout, hermesExecutionProbePipeWait = timeout, pipeWait
	t.Cleanup(func() {
		hermesExecutionProbeTimeout, hermesExecutionProbePipeWait = previousTimeout, previousPipeWait
	})
}

// A registered hook that writes far more than the proof must neither grow
// Verify's memory with its output nor keep Verify running until the timeout.
func TestHermesExecutionProbeCapsCapturedOutput(t *testing.T) {
	setHermesExecutionProbeBounds(t, 20*time.Second, time.Second)
	for name, body := range map[string]string{
		"proof then 64 MiB": "printf 'defenseclaw-execution-probe-ok\\n'\nhead -c 67108864 /dev/zero\n",
		"64 MiB then proof": "set -e\nhead -c 67108864 /dev/zero\nprintf 'defenseclaw-execution-probe-ok\\n'\n",
		"endless stream":    "printf 'defenseclaw-execution-probe-ok\\n'\nexec yes\n",
	} {
		t.Run(name, func(t *testing.T) {
			script := writeHermesProbeScript(t, body)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			ok := runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe"})
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if ok {
				t.Fatal("probe with oversized output passed")
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
				t.Fatalf("probe allocated %d bytes for oversized output; want it capped", grew)
			}
			if elapsed > 10*time.Second {
				t.Fatalf("probe took %s; an output overflow must end it before the timeout", elapsed)
			}
		})
	}
}

// Neither a hook that exits while a descendant keeps stdout open nor a hung
// tree may hold Verify past the timeout plus the pipe wait.
func TestHermesExecutionProbeBoundsInheritedStdout(t *testing.T) {
	for name, tc := range map[string]struct {
		body    string
		timeout time.Duration
	}{
		"exits, descendant holds stdout":     {"printf 'defenseclaw-execution-probe-ok\\n'\nsleep 20 &\nexit 0\n", 20 * time.Second},
		"hangs, descendant holds stdout":     {"sleep 20 &\nsleep 20\n", 300 * time.Millisecond},
		"hangs after proof, ignores SIGTERM": {"trap '' TERM\nprintf 'defenseclaw-execution-probe-ok\\n'\nsleep 20 &\nsleep 20\n", 300 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			setHermesExecutionProbeBounds(t, tc.timeout, 500*time.Millisecond)
			script := writeHermesProbeScript(t, tc.body)
			done := make(chan bool, 1)
			start := time.Now()
			go func() { done <- runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe"}) }()
			select {
			case ok := <-done:
				if elapsed := time.Since(start); elapsed > 5*time.Second {
					t.Fatalf("probe took %s; want it bounded by the timeout and pipe wait", elapsed)
				}
				if tc.timeout < time.Second && ok {
					t.Fatal("timed-out probe passed")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("probe still waiting on an inherited stdout after 15s")
			}
		})
	}
}

// r104 W5b: a hook that prints the proof and leaves a child running, or
// hangs, or floods stdout, must not leave what it started running after
// Verify, one more for each check. On macOS RunTree had no process group.
func TestHermesExecutionProbeEndsWhatTheHookStarted(t *testing.T) {
	const (
		proof = "printf 'defenseclaw-execution-probe-ok\\n'\n"
		// The child writes its pid as this test sees it ($! counts in the
		// probe's PID namespace on Linux), then runs as sleep.
		writePID = `read -r p _ < /proc/self/stat; echo $p > "$PIDFILE"; `
		child    = "( " + writePID + "exec sleep 60 )"
		waitPID  = "while [ ! -s \"$PIDFILE\" ]; do sleep 0.01; done\n"
	)
	for name, tc := range map[string]struct {
		body    string
		timeout time.Duration
	}{
		"exits, child holds stdout":        {proof + child + " &\n" + waitPID + "exit 0\n", 20 * time.Second},
		"exits, child detached":            {proof + child + " >/dev/null 2>&1 &\n" + waitPID + "exit 0\n", 20 * time.Second},
		"exits, grandchild":                {proof + "( " + child + " & )\n" + waitPID + "exit 0\n", 20 * time.Second},
		"times out":                        {child + " &\nwait\n", 300 * time.Millisecond},
		"overflows":                        {proof + child + " &\n" + waitPID + "exec yes\n", 20 * time.Second},
		"exits, child ignores hangup/term": {proof + "( trap '' HUP TERM; " + writePID + "exec sleep 60 ) &\n" + waitPID + "exit 0\n", 20 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			timeout := tc.timeout
			if runtime.GOOS == "darwin" {
				timeout = 500 * time.Millisecond
			}
			setHermesExecutionProbeBounds(t, timeout, 500*time.Millisecond)
			pidFile := filepath.Join(testenv.PrivateTempDir(t), "descendant.pid")
			script := writeHermesProbeScript(t, "PIDFILE='"+pidFile+"'\n"+tc.body)
			runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe"})
			if runtime.GOOS == "darwin" {
				if pid := optionalHermesProbePID(pidFile); pid > 0 && hermesProbeProcessRunning(pid) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("forkless Verify started descendant %d", pid)
				}
				return
			}
			pid := readHermesProbePID(t, pidFile)
			deadline := time.Now().Add(5 * time.Second)
			for hermesProbeProcessRunning(pid) {
				if time.Now().After(deadline) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("Verify's probe left descendant %d running", pid)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

func optionalHermesProbePID(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}

func readHermesProbePID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && convErr == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe never wrote %s: %v", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// hermesProbeProcessRunning reports a live process; a zombie is not (Linux
// /proc state Z; elsewhere init reaps the reparented child).
func hermesProbeProcessRunning(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return true
	}
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
	return len(fields) == 0 || fields[0] != "Z"
}

// r104 W5b: a sealed, approved hook can start a child out of the process
// group (a new session, its own group, a double fork) and redirect its
// streams; Verify passed while the child kept running. On Linux the probe
// must end it and may pass only once nothing is left. On macOS the probe
// cannot create a child in the first place.
func TestHermesExecutionProbeEndsDescendantsThatLeaveTheGroup(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed")
	}
	const (
		proof   = "printf 'defenseclaw-execution-probe-ok\\n'\n"
		session = `perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die' `
		group   = `perl -e 'setpgrp(0, 0) or die; exec @ARGV or die' `
		// The pid as this test sees it: $$ counts in the probe's PID
		// namespace on Linux.
		child  = `sh -c 'read -r p _ < /proc/self/stat; echo $p > "$0"; exec sleep 60' "$PIDFILE" </dev/null >/dev/null 2>&1`
		closed = `sh -c 'read -r p _ < /proc/self/stat; echo $p > "$0"; exec sleep 60 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-' "$PIDFILE" </dev/null >/dev/null 2>&1`
		// Every supervisor ancestor by the pids this test sees, outermost
		// first, SIGKILLed together: a hook that killed the subreaper
		// custodian, its grandparent, left its setsid child running (r104
		// W5b review).
		killSupervisors = `read -r _ _ _ a _ < /proc/self/stat; list=""
while [ "${a:-0}" -gt 1 ]; do
  case "$(tr '\0' ' ' < /proc/$a/cmdline)" in defenseclaw-contained-run*) list="$a $list" ;; esac
  read -r _ _ _ a _ < /proc/$a/stat || break
done
[ -n "$list" ] || exit 7
kill -9 $list
sleep 1
`
		waitPID  = "while [ ! -s \"$PIDFILE\" ]; do sleep 0.01; done\n"
		exitZero = "exit 0\n"
	)
	for name, tc := range map[string]struct {
		body    string
		timeout time.Duration
		proves  bool
	}{
		"new session":                    {proof + session + child + " &\n" + waitPID + exitZero, 20 * time.Second, true},
		"double fork into a new session": {proof + "( " + session + child + " & )\n" + waitPID + exitZero, 20 * time.Second, true},
		"own process group":              {proof + group + child + " &\n" + waitPID + exitZero, 20 * time.Second, true},
		"new session, descriptors closed": {
			proof + session + closed + " &\n" + waitPID + exitZero, 20 * time.Second, true,
		},
		"new session, then times out":  {session + child + " &\n" + waitPID + "sleep 60\n", 500 * time.Millisecond, false},
		"new session, then overflows":  {proof + session + child + " &\n" + waitPID + "exec yes\n", 20 * time.Second, false},
		"new session, then hook fails": {proof + session + child + " &\n" + waitPID + "exit 1\n", 20 * time.Second, false},
		"new session, then kills every supervisor": {
			proof + session + child + " &\n" + waitPID + killSupervisors + exitZero, 20 * time.Second, true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			timeout := tc.timeout
			if runtime.GOOS == "darwin" {
				timeout = 500 * time.Millisecond
			}
			setHermesExecutionProbeBounds(t, timeout, 500*time.Millisecond)
			pidFile := filepath.Join(testenv.PrivateTempDir(t), "escaped.pid")
			script := writeHermesProbeScript(t, "PIDFILE='"+pidFile+"'\n"+tc.body)
			ok := runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe"})
			if runtime.GOOS == "darwin" {
				if pid := optionalHermesProbePID(pidFile); pid > 0 && hermesProbeProcessRunning(pid) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("forkless Verify started descendant %d", pid)
				}
				return
			}
			pid := readHermesProbePID(t, pidFile)
			running := hermesProbeProcessRunning(pid)
			_ = syscall.Kill(pid, syscall.SIGKILL)
			if running {
				t.Fatalf("Verify's probe left descendant %d running", pid)
			}
			if ok != tc.proves {
				t.Fatalf("probe = %v, want %v", ok, tc.proves)
			}
		})
	}
}
