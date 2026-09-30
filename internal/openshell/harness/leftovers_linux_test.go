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

//go:build linux

package harness

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// procAlive reports whether pid runs (a zombie has ended).
func procAlive(pid int) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(raw)
	fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// leftoverPIDs reads the pids a stub recorded in dir/leftover, and kills
// whatever of them still runs when the test ends.
func leftoverPIDs(t *testing.T, dir string, want int) []int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "leftover"))
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("leftover %q: %v", f, err)
		}
		pids = append(pids, pid)
	}
	t.Cleanup(func() {
		for _, pid := range pids {
			if procAlive(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	if len(pids) != want {
		t.Fatalf("the stub recorded %d leftovers, want %d: %q", len(pids), want, raw)
	}
	return pids
}

// stubLeaves leaves three commands running when it exits, as a harness that
// quits in the middle of tool calls does: one in a session of its own (the
// way OpenCode starts its shell tool), one in the harness's process group
// that ignores the group's SIGHUP, and one that ignores SIGTERM too. It
// waits long enough for the supervisor's scan to see them, then exits 3.
const stubLeaves = `/usr/bin/python3 -c 'import os; os.setsid(); os.execvp("sleep", ["sleep", "60"])' &
echo $! >>"${0%/*}/leftover"
( trap '' HUP; exec sleep 61 ) &
echo $! >>"${0%/*}/leftover"
( trap '' HUP TERM; exec sleep 62 ) &
echo $! >>"${0%/*}/leftover"
sleep 1.5
exit 3
`

// TestLauncherEndsWhatTheHarnessLeftRunning: once a supervised harness
// exits, the commands it left running are ended before the launcher exits
// (so before DefenseClaw pulls or reviews the session's work), and the
// terminal names them; with the subreaper refused, the supervisor still
// ends what it saw below the harness. What ends on its own within the grace
// is not named, and the sandbox exec wrapper keeps what its command left.
func TestLauncherEndsWhatTheHarnessLeftRunning(t *testing.T) {
	requireBash(t)
	defaultDisposition(t)
	const ended = "defenseclaw: the harness exited with 3 commands still running in the sandbox; ended them"
	check := func(t *testing.T, r *ptyRun, dir string) {
		t.Helper()
		start := time.Now()
		code, out := r.wait()
		if code != 3 {
			t.Fatalf("exit %d, want the stub's 3:\n%s", code, out)
		}
		for _, pid := range leftoverPIDs(t, dir, 3) {
			if procAlive(pid) {
				t.Errorf("leftover %d still runs after the launcher exited:\n%s", pid, out)
			}
		}
		if !strings.Contains(out, ended) || !strings.Contains(out, "sleep 60; sleep 61; sleep 62") {
			t.Errorf("the terminal does not name the ended commands (%q):\n%s", ended, out)
		}
		if took := time.Since(start); took > 15*time.Second {
			t.Errorf("ending the leftovers took %s", took)
		}
	}

	t.Run("with the subreaper", func(t *testing.T) {
		launcher, dir := launcherFixture(t, ClaudeCode, stubLeaves)
		// The caller's environment cannot keep them.
		check(t, startPTY(t, dir, []string{"dc_keep_leftovers=1"}, launcher), dir)
	})

	t.Run("without the subreaper", func(t *testing.T) {
		launcher, dir := launcherFixture(t, ClaudeCode, stubLeaves)
		supervisor := filepath.Join(dir, filepath.FromSlash(SupervisorPath))
		raw, err := os.ReadFile(supervisor)
		if err != nil {
			t.Fatal(err)
		}
		// prctl refuses an unknown option, as a filter refusing it would.
		refused := strings.Replace(string(raw), "PR_SET_CHILD_SUBREAPER = 36", "PR_SET_CHILD_SUBREAPER = -1", 1)
		if refused == string(raw) {
			t.Fatal("the supervisor sets no PR_SET_CHILD_SUBREAPER")
		}
		if err := os.WriteFile(supervisor, []byte(refused), 0o755); err != nil {
			t.Fatal(err)
		}
		check(t, startPTY(t, dir, nil, launcher), dir)
	})

	t.Run("what ends on its own is not named", func(t *testing.T) {
		launcher, dir := launcherFixture(t, ClaudeCode, "( trap '' HUP; exec sleep 0.3 ) &\nexit 0\n")
		code, out := startPTY(t, dir, nil, launcher).wait()
		if code != 0 || strings.Contains(out, "defenseclaw:") {
			t.Fatalf("exit %d, want 0 and no notice:\n%s", code, out)
		}
	})

	// It names what stays in the terminal's session, which holds
	// OpenShell's --tty exec open for about 30 seconds and then ends it
	// with status 74 and no word (retest H-RT-2: `sandbox exec --tty --
	// bash -c 'nohup sleep 304 >/dev/null 2>&1 & exit'`). What the exit's
	// SIGHUP ends is not named.
	for _, tc := range []struct {
		name, stub, notice string
		kept               bool
	}{
		{"the sandbox exec wrapper keeps them", "( trap '' HUP; exec sleep 60 ) &", "left 1 process running in the sandbox: sleep 60. It keeps running", true},
		{"a nohup'd command", "nohup sleep 61 >/dev/null 2>&1 &", "left 1 process running in the sandbox: sleep 61. It keeps running", true},
		{"what the hangup ends", "sleep 62 &", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			wrapper := filepath.Join(dir, "sandbox-env")
			supervisor := filepath.Join(dir, "dc_supervisor.py")
			if err := os.WriteFile(supervisor, shellFile(t, Codex, SupervisorPath).Data, 0o755); err != nil {
				t.Fatal(err)
			}
			script := strings.ReplaceAll(string(shellFile(t, Codex, SandboxEnvPath).Data), SupervisorPath, supervisor)
			if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			stub := filepath.Join(dir, "stub")
			if err := os.WriteFile(stub, []byte("#!/bin/bash\n"+tc.stub+"\necho $! >\"${0%/*}/leftover\"\nexit 3\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			code, out := startPTY(t, dir, nil, wrapper, stub).wait()
			if code != 3 {
				t.Fatalf("exit %d, want the stub's 3:\n%s", code, out)
			}
			pids := leftoverPIDs(t, dir, 1)
			if alive := procAlive(pids[0]); alive != tc.kept {
				t.Errorf("the command's leftover %d running = %v, want %v", pids[0], alive, tc.kept)
			}
			switch {
			case tc.notice == "" && strings.Contains(out, "defenseclaw:"):
				t.Errorf("a notice for what the hangup ended:\n%s", out)
			case tc.notice != "" && (!strings.Contains(out, "defenseclaw: the command "+tc.notice) || !strings.Contains(out, "(then status 74)")):
				t.Errorf("the terminal does not name the kept process (%q):\n%s", tc.notice, out)
			}
		})
	}
}
