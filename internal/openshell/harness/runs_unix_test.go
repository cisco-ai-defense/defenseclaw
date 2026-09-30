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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// runState runs run_state on dir, as the CLI does (mark false) or as the
// daemon's stop does (mark true), and parses what it printed.
func runState(t *testing.T, dir string, mark bool) DetachedRun {
	t.Helper()
	return runStateIn(t, "/bin/sh", dir, mark)
}

// runStateIn is runState in the shell sh, bounded: run_state must never
// wait on what the workload left in the run directory.
func runStateIn(t *testing.T, sh, dir string, mark bool) DetachedRun {
	t.Helper()
	call := `run_state "$1"`
	if mark {
		call += " mark"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, sh, "-c", RunStateFunc+call+"\n", "sh", dir).Output()
	if err != nil {
		t.Fatalf("run_state in %s: %v\n%s", sh, err, out)
	}
	return ParseRun(out)
}

// shells are the POSIX shells on this machine the scripts run in: /bin/sh,
// and dash, the sh of Debian-based images, where it is installed.
func shells(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, sh := range []string{"/bin/sh", "/bin/dash", "/usr/bin/dash"} {
		if _, err := os.Stat(sh); err == nil {
			out = append(out, sh)
		}
	}
	if len(out) == 0 {
		t.Skip("/bin/sh is required")
	}
	return out
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

// The run directory is the workload's: a FIFO or a link to a device where a
// run file should be, whether planted or swapped in after a look, never
// holds run_state (a stop, `sandbox stop`'s question), which reads only
// what is a regular file as it opens it and writes its mark without
// waiting for a reader.
func TestRunStateNeverWaitsOnTheWorkload(t *testing.T) {
	for _, sh := range shells(t) {
		for _, file := range []string{"latest.pid", "latest.exit", "latest.started"} {
			for _, kind := range []string{"fifo", "device"} {
				t.Run(filepath.Base(sh)+"/"+file+"/"+kind, func(t *testing.T) {
					d := runDir(t, true, "")
					path := filepath.Join(d, file)
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
					if kind == "fifo" {
						if err := syscall.Mkfifo(path, 0o600); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Symlink("/dev/zero", path); err != nil {
						t.Fatal(err)
					}
					cli := runStateIn(t, sh, d, false)
					stop := runStateIn(t, sh, d, true)
					if cli.State == sandboxapi.RunNone || stop.State == sandboxapi.RunNone || cli.Exit != "" {
						t.Fatalf("the CLI reads %+v, the stop %+v", cli, stop)
					}
					if file == "latest.pid" && stop.State != sandboxapi.RunInterrupted {
						t.Fatalf("a run without a readable pid reads %+v", stop)
					}
					if file == "latest.started" && stop.Started != 0 {
						t.Fatalf("a start read from a %s: %+v", kind, stop)
					}
					if info, err := os.Lstat(path); err != nil || (kind == "fifo") != (info.Mode()&os.ModeNamedPipe != 0) {
						t.Fatalf("%s was replaced: %v, %v", file, info, err)
					}
				})
			}
		}
	}
}

// The scripts work alike in each shell a sandbox image may have as sh.
func TestRunStateInEachShell(t *testing.T) {
	for _, sh := range shells(t) {
		d := runDir(t, true, "")
		if got := runStateIn(t, sh, d, true); got != (DetachedRun{State: sandboxapi.RunRunning, Started: 1790000000}) {
			t.Fatalf("%s: a live run reads %+v", sh, got)
		}
		if exit, _ := os.ReadFile(filepath.Join(d, "latest.exit")); string(exit) != "interrupted\n" {
			t.Fatalf("%s: latest.exit = %q after the stop's look", sh, exit)
		}
		if got := runStateIn(t, sh, runDir(t, false, "7\n"), false); got != (DetachedRun{State: sandboxapi.RunExited, Exit: "7", Started: 1790000000}) {
			t.Fatalf("%s: an exited run reads %+v", sh, got)
		}
	}
}

// rs_open checks what it opened, not what was there when the caller looked:
// a FIFO or a device swapped in after the look is refused at once, not
// waited on, and a link to a regular file (latest.log links to the dated
// log) is read.
func TestRsOpenRefusesWhatIsNotARegularFile(t *testing.T) {
	d := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(d, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(d, "zero")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "dated.log"), []byte("0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(d, "dated.log"), filepath.Join(d, "latest.log")); err != nil {
		t.Fatal(err)
	}
	for _, sh := range shells(t) {
		for name, want := range map[string]string{"fifo": "refused\n", "zero": "refused\n", "latest.log": "opened 6789\n"} {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			script := RunReadFunc + `if rs_open "$1"; then printf 'opened '; /usr/bin/tail -c 5 <&3; else echo refused; fi` + "\n"
			out, err := exec.CommandContext(ctx, sh, "-c", script, "sh", filepath.Join(d, name)).Output()
			cancel()
			if err != nil || string(out) != want {
				t.Fatalf("%s: rs_open %s: %q, %v; want %q", sh, name, out, err, want)
			}
		}
	}
}
