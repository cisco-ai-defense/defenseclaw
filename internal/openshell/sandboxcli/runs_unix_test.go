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

//go:build unix

package sandboxcli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runRunScript runs one of the detached-run scripts the way the sandbox
// does and returns its output.
func runRunScript(t *testing.T, script string, args ...string) string {
	t.Helper()
	out, err := exec.Command("/bin/sh", append([]string{"-c", script, "sh"}, args...)...).Output()
	if err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	return string(out)
}

// A detached run a stop ended read "exited with status 143" once the
// sandbox started again (the live CLI test): the stop lets the harness exit
// on SIGTERM before the sandbox goes, and the run's runner wrote that
// status over the "interrupted" the stop had marked. The runner keeps the
// mark; a run that ends by itself, or on a signal no stop sent, still
// records its own status.
func TestDetachedRunKeepsTheStopsInterruptedMark(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	for _, c := range []struct {
		name      string
		mark      bool
		terminate bool
		want      detachedRun
	}{
		{"a stop marks it, then ends the harness", true, true, detachedRun{State: runInterrupted}},
		{"a signal no stop sent", false, true, detachedRun{State: runExited, Exit: "143"}},
		{"it ends by itself", false, false, detachedRun{State: runExited, Exit: "5"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "runs")
			pidFile := filepath.Join(t.TempDir(), "harness.pid")
			harnessArgv := []string{"/bin/sh", "-c", `echo $$ > "$1"; exec sleep 30`, "harness", pidFile}
			if !c.terminate {
				harnessArgv = []string{"/bin/sh", "-c", `echo done; exit 5`}
			}
			runRunScript(t, detachScript, append([]string{dir}, harnessArgv...)...)
			state := func() detachedRun {
				t.Helper()
				return parseDetachedRun(runRunScript(t, runStateScript, dir))
			}
			if c.terminate {
				var pid int
				for deadline := time.Now().Add(10 * time.Second); pid == 0; time.Sleep(20 * time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatal("the harness never started")
					}
					data, _ := os.ReadFile(pidFile)
					pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
				}
				t.Cleanup(func() {
					if state().State == runRunning {
						_ = syscall.Kill(pid, syscall.SIGKILL)
					}
				})
				if got := state(); got.State != runRunning || got.Started == 0 {
					t.Fatalf("the started run reads %+v", got)
				}
				if c.mark {
					runRunScript(t, runMarkScript, dir)
				}
				// What the daemon's stop does before the sandbox goes.
				if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			got := state()
			for deadline := time.Now().Add(10 * time.Second); got.State == runRunning; got = state() {
				if time.Now().After(deadline) {
					t.Fatal("the runner did not end with its harness")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if got.State != c.want.State || got.Exit != c.want.Exit {
				exit, _ := os.ReadFile(filepath.Join(dir, "latest.exit"))
				t.Fatalf("the ended run reads %+v (latest.exit %q), want %s %s", got, exit, c.want.State, c.want.Exit)
			}
		})
	}
}
