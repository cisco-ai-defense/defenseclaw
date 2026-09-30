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

//go:build !windows

package manager

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// runDirSandbox runs the stop's in-sandbox scripts (endHarnessScript,
// runLogScript) on this machine, against runs in place of harness.RunDir:
// what the manager keeps is what the scripts found.
func runDirSandbox(t *testing.T, e *harnessEnv, runs string) {
	t.Helper()
	e.fake.HandleExec(func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		argv := slices.Clone(call.Command)
		if len(argv) < 4 || argv[0] != "/bin/sh" || argv[1] != "-c" {
			return openshelltest.ExecResponse{}
		}
		for i, a := range argv {
			if a == harness.RunDir {
				argv[i] = runs
			}
		}
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		out, err := cmd.Output()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			return openshelltest.ExecResponse{Err: err}
		}
		return openshelltest.ExecResponse{Stdout: out, ExitCode: code}
	})
}

// detachedRunDir writes a detached run's files as `sandbox run --detach`
// leaves them: the log (latest.log links to it), the start and, for a
// finished run, the exit status.
func detachedRunDir(t *testing.T, log, exit string) string {
	t.Helper()
	d := t.TempDir()
	dated := writeFile(t, filepath.Join(d, "20260930T100000Z.log"), log)
	must(t, os.Symlink(dated, filepath.Join(d, "latest.log")))
	writeFile(t, filepath.Join(d, "latest.started"), "1790000000\n")
	if exit != "" {
		writeFile(t, filepath.Join(d, "latest.exit"), exit)
	}
	return d
}

// liveRunner starts a process that stands in for a detached run's runner
// (its command line names latest.exit) and records its pid.
func liveRunner(t *testing.T, d string) {
	t.Helper()
	runner := exec.Command("/bin/sh", "-c", "sleep 60; true", "sh", filepath.Join(d, "latest.exit"))
	must(t, runner.Start())
	t.Cleanup(func() { _ = runner.Process.Kill(); _ = runner.Wait() })
	writeFile(t, filepath.Join(d, "latest.pid"), strconv.Itoa(runner.Process.Pid)+"\n")
}

// goneRunner records the pid of a runner that has exited.
func goneRunner(t *testing.T, d string) {
	t.Helper()
	gone := exec.Command("/bin/sh", "-c", "exit 0")
	must(t, gone.Run())
	writeFile(t, filepath.Join(d, "latest.pid"), strconv.Itoa(gone.Process.Pid)+"\n")
}

// Every stop through the daemon, whoever asks for it, keeps the log of the
// sandbox's latest detached run (M1 used to live in the CLI only, so a stop
// from the TUI, the macOS app, undo or a tamper stop lost it): a run still
// going is marked interrupted and said on the feed, a finished one keeps its
// status, and `GET …/logs` serves the log, its last lines on request. A
// delete removes it.
func TestStopKeepsTheDetachedRunLog(t *testing.T) {
	e := liveEnv(t, "runbox", nil)
	going := detachedRunDir(t, "working\nstill working\n", "")
	liveRunner(t, going)
	runDirSandbox(t, e, going)
	if _, err := e.m.RunLog(t.Context(), "runbox", 0); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("run log before any stop: %v", err)
	}
	e.stopBox("runbox")
	if data, err := os.ReadFile(filepath.Join(going, "latest.exit")); err != nil || string(data) != "interrupted\n" {
		t.Fatalf("latest.exit = %q, %v; want the run marked interrupted", data, err)
	}
	log, err := e.m.RunLog(t.Context(), "runbox", 0)
	if err != nil || log.State != sandboxapi.RunInterrupted || log.Log != "working\nstill working\n" ||
		!log.StartedAt.Equal(time.Unix(1790000000, 0)) || log.KeptAt.IsZero() {
		t.Fatalf("run log = %+v, %v", log, err)
	}
	if last, err := e.m.RunLog(t.Context(), "runbox", 1); err != nil || last.Log != "still working\n" {
		t.Fatalf("last line = %+v, %v", last, err)
	}
	if !slices.ContainsFunc(e.events("runbox", sandboxapi.ActivityLifecycle, "run_interrupted"), func(ev sandboxapi.ActivityEvent) bool {
		return strings.Contains(ev.Message, "defenseclaw sandbox logs runbox")
	}) {
		t.Fatal("the feed does not say the stop ended the detached run")
	}

	// A run that finished keeps its status; undo's stop keeps it too.
	e.startBox("runbox", sandboxapi.StartRequest{})
	finished := detachedRunDir(t, "done\n", "0\n")
	goneRunner(t, finished)
	runDirSandbox(t, e, finished)
	if _, err := e.m.Undo(t.Context(), "runbox", sandboxapi.UndoRequest{Stop: true}); err != nil {
		t.Fatal(err)
	}
	if log, err := e.m.RunLog(t.Context(), "runbox", 0); err != nil || log.State != sandboxapi.RunExited || log.Exit != "0" || log.Log != "done\n" {
		t.Fatalf("run log after undo = %+v, %v", log, err)
	}
	if n := len(e.events("runbox", sandboxapi.ActivityLifecycle, "run_interrupted")); n != 1 {
		t.Fatalf("%d run_interrupted events; a finished run was said to be ended", n)
	}
	// A later stop finds the same finished run: its log is kept as it is.
	reads := func() int {
		return len(slices.DeleteFunc(e.fake.ExecCalls(), func(c openshelltest.ExecCall) bool {
			return !slices.Contains(c.Command, "defenseclaw-run-log")
		}))
	}
	before := reads()
	e.startBox("runbox", sandboxapi.StartRequest{})
	e.stopBox("runbox")
	if reads() != before {
		t.Fatal("a stop read the log of a run already kept again")
	}
	if log, err := e.m.RunLog(t.Context(), "runbox", 0); err != nil || log.State != sandboxapi.RunExited || log.Log != "done\n" {
		t.Fatalf("run log after another stop = %+v, %v", log, err)
	}

	dir := filepath.Join(e.dataDir, "sandboxes", "runbox", runLogDirName)
	if !fileExists(filepath.Join(dir, runLogMetaFile)) {
		t.Fatal("no kept run log on disk")
	}
	e.deleteBox("runbox", sandboxapi.DeleteRequest{})
	if fileExists(dir) {
		t.Fatal("the kept run log outlived the sandbox")
	}
}

// A stop without a detached run keeps nothing and reads nothing more; a run
// whose runner is gone and never wrote a status (the sandbox stopped under
// it) reads interrupted without a feed notice.
func TestStopWithoutALiveRun(t *testing.T) {
	e := liveEnv(t, "quietbox", nil)
	runDirSandbox(t, e, t.TempDir())
	e.stopBox("quietbox")
	if calls := e.fake.ExecCalls(); len(calls) != 1 {
		t.Fatalf("exec calls = %d, want only the harness's end", len(calls))
	}
	if _, err := e.m.RunLog(t.Context(), "quietbox", 0); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("run log of a sandbox without a run: %v", err)
	}
	e.startBox("quietbox", sandboxapi.StartRequest{})
	gone := detachedRunDir(t, "partial\n", "")
	goneRunner(t, gone)
	runDirSandbox(t, e, gone)
	e.stopBox("quietbox")
	if log, err := e.m.RunLog(t.Context(), "quietbox", 0); err != nil || log.State != sandboxapi.RunInterrupted || log.Log != "partial\n" {
		t.Fatalf("run log = %+v, %v", log, err)
	}
	if n := len(e.events("quietbox", sandboxapi.ActivityLifecycle, "run_interrupted")); n != 0 {
		t.Fatalf("%d run_interrupted events for a run that was not going", n)
	}
}

// A kept log belongs to the OpenShell sandbox it came from.
func TestRunLogIsTiedToTheSandbox(t *testing.T) {
	e := liveEnv(t, "tiedbox", nil)
	b := e.boxOf("tiedbox")
	e.m.mu.Lock()
	b.rec.ID = "sb-tied"
	e.m.mu.Unlock()
	must(t, e.m.saveRunLog("tiedbox", keptRun{SandboxID: "sb-another", State: sandboxapi.RunExited, Exit: "0", KeptAt: time.Now()}, []byte("x\n")))
	if _, err := e.m.RunLog(t.Context(), "tiedbox", 0); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("another sandbox's log was served: %v", err)
	}
	must(t, e.m.saveRunLog("tiedbox", keptRun{SandboxID: "sb-tied", State: sandboxapi.RunExited, Exit: "0", KeptAt: time.Now()}, []byte("x\n")))
	if log, err := e.m.RunLog(t.Context(), "tiedbox", 0); err != nil || log.Log != "x\n" {
		t.Fatalf("its own log = %+v, %v", log, err)
	}
}

// The script reports the detached run the stop finds: a live runner (its
// command line names latest.exit) is going and gets marked, a finished run
// keeps its status, a runner that is gone without one reads interrupted,
// and a sandbox without a run prints nothing about one.
func TestEndHarnessScriptReportsTheDetachedRun(t *testing.T) {
	root := filepath.Join(t.TempDir(), "no-harness")
	end := func(runs string) harnessEnd {
		t.Helper()
		out, err := exec.Command("/bin/sh", "-c", endHarnessScript, "defenseclaw-end-harness", root, "1", runs).Output()
		must(t, err)
		return parseHarnessEnd(out)
	}
	going := detachedRunDir(t, "x\n", "")
	liveRunner(t, going)
	finished := detachedRunDir(t, "x\n", "3\n")
	goneRunner(t, finished)
	gone := detachedRunDir(t, "x\n", "")
	goneRunner(t, gone)
	for _, c := range []struct {
		name string
		runs string
		want detachedRun
	}{
		{"going", going, detachedRun{State: runRunning, Started: 1790000000}},
		{"finished", finished, detachedRun{State: runExited, Exit: "3", Started: 1790000000}},
		{"gone", gone, detachedRun{State: runInterrupted, Started: 1790000000}},
		{"none", t.TempDir(), detachedRun{State: runNone}},
	} {
		if got := end(c.runs); got.Harness != "none" || got.Run != c.want {
			t.Fatalf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	for dir, want := range map[string]string{going: "interrupted\n", finished: "3\n", gone: "interrupted\n"} {
		if data, err := os.ReadFile(filepath.Join(dir, "latest.exit")); err != nil || string(data) != want {
			t.Fatalf("latest.exit = %q, %v; want %q", data, err, want)
		}
	}
	// What the workload writes there is read as a status, not as output.
	odd := detachedRunDir(t, "x\n", "0 run=running\n")
	if got := end(odd); got.Run.State != runExited || got.Run.Exit != "0runrunning" {
		t.Fatalf("odd status: %+v", got.Run)
	}
}

func TestParseHarnessEnd(t *testing.T) {
	got := parseHarnessEnd([]byte("run_exit=0\nrun=exited\nrun_started=12\nexited\nsynced\n"))
	if got.Harness != "exited" || !got.Synced || got.Run != (detachedRun{State: runExited, Exit: "0", Started: 12}) {
		t.Fatalf("parsed %+v", got)
	}
	if got := parseHarnessEnd([]byte("running\n")); got.Harness != "running" || got.Synced || got.Run.State != runNone {
		t.Fatalf("parsed %+v", got)
	}
}
