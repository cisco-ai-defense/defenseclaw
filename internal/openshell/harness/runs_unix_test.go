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

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// runState runs run_state on dir, as the CLI does (mark false) or as the
// daemon's stop does (mark true), and parses what it printed.
func runState(t *testing.T, dir string, mark bool) DetachedRun {
	t.Helper()
	call := `run_state "$1"`
	if mark {
		call += " mark"
	}
	out, err := exec.Command("/bin/sh", "-c", RunStateFunc+call+"\n", "sh", dir).Output()
	if err != nil {
		t.Fatalf("run_state: %v\n%s", err, out)
	}
	return ParseRun(out)
}

// runDir writes a detached run's files as `sandbox run --detach` leaves
// them: the log (latest.log links to it), the start and, when exit is set,
// the exit status; live starts a process standing in for its runner (its
// command line names latest.exit), otherwise the pid is one that is gone.
func runDir(t *testing.T, live bool, exit string) string {
	t.Helper()
	d := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(d, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("20260930T100000Z.log", "x\n")
	if err := os.Symlink(filepath.Join(d, "20260930T100000Z.log"), filepath.Join(d, "latest.log")); err != nil {
		t.Fatal(err)
	}
	write("latest.started", "1790000000\n")
	if exit != "" {
		write("latest.exit", exit)
	}
	runner := exec.Command("/bin/sh", "-c", "exit 0")
	if live {
		runner = exec.Command("/bin/sh", "-c", "sleep 60; true", "sh", filepath.Join(d, "latest.exit"))
		if err := runner.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runner.Process.Kill(); _ = runner.Wait() })
	} else if err := runner.Run(); err != nil {
		t.Fatal(err)
	}
	write("latest.pid", strconv.Itoa(runner.Process.Pid)+"\n")
	return d
}

// The CLI (`sandbox stop`'s question, `sandbox logs`) and the daemon's stop
// read a run the same way: a live runner whose run already recorded a
// status of its own reads exited in both (the CLI used to call it running
// and ask whether to stop it), and only the stop marks a run it ends.
func TestRunStateAgreesForTheCLIAndTheStop(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	started := int64(1790000000)
	for _, c := range []struct {
		name     string
		live     bool
		exit     string
		want     DetachedRun
		markedAs string
	}{
		{"going", true, "", DetachedRun{State: sandboxapi.RunRunning, Started: started}, "interrupted\n"},
		{"going, its status recorded", true, "0\n", DetachedRun{State: sandboxapi.RunExited, Exit: "0", Started: started}, "0\n"},
		{"going, marked by a stop that failed", true, "interrupted\n", DetachedRun{State: sandboxapi.RunRunning, Started: started}, "interrupted\n"},
		{"exited", false, "3\n", DetachedRun{State: sandboxapi.RunExited, Exit: "3", Started: started}, "3\n"},
		{"gone without a status", false, "", DetachedRun{State: sandboxapi.RunInterrupted, Started: started}, "interrupted\n"},
		{"an odd status", false, "0 run=running\n", DetachedRun{State: sandboxapi.RunExited, Exit: "0runrunning", Started: started}, "0 run=running\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := runDir(t, c.live, c.exit)
			cli := runState(t, d, false)
			if exit, _ := os.ReadFile(filepath.Join(d, "latest.exit")); string(exit) != c.exit {
				t.Fatalf("the CLI's look changed latest.exit to %q", exit)
			}
			stop := runState(t, d, true)
			if cli != c.want || stop != c.want {
				t.Fatalf("the CLI reads %+v, the stop %+v; want %+v", cli, stop, c.want)
			}
			if exit, _ := os.ReadFile(filepath.Join(d, "latest.exit")); string(exit) != c.markedAs {
				t.Fatalf("latest.exit after the stop's look = %q, want %q", exit, c.markedAs)
			}
		})
	}
	if got := runState(t, t.TempDir(), true); got != (DetachedRun{State: sandboxapi.RunNone}) {
		t.Fatalf("a sandbox without a run reads %+v", got)
	}
}
