// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const independentBase = uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)

func TestStartIndependentDecidesFromTheEnclosingJob(t *testing.T) {
	membershipUnknown := errors.New("IsProcessInJob failed")
	for _, tc := range []struct {
		name        string
		limits      uint32
		queryErr    error
		selfInJob   bool
		inJobErr    error
		accepted    bool
		wantFlags   uint32
		wantProbe   bool
		wantStarted bool
		wantBound   bool
	}{
		{name: "no job", queryErr: windows.ERROR_INVALID_HANDLE, wantFlags: independentBase, wantStarted: true},
		{name: "breakaway allowed", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
			wantFlags: independentBase | windows.CREATE_BREAKAWAY_FROM_JOB, wantStarted: true},
		{name: "silent breakaway", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
			wantFlags: independentBase, wantStarted: true},
		{name: "job that outlives its handle", wantFlags: independentBase, wantStarted: true},
		{name: "kill on close, no breakaway", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, wantBound: true},
		// GAP-0960: a LocalSystem scheduled task cannot read its own job.
		// It can still start recovery when it is in no job or can break away.
		{name: "unreadable job, breakaway accepted", queryErr: windows.ERROR_ACCESS_DENIED, selfInJob: true, accepted: true,
			wantProbe: true, wantFlags: independentBase | windows.CREATE_BREAKAWAY_FROM_JOB, wantStarted: true},
		{name: "unreadable job, breakaway refused", queryErr: windows.ERROR_ACCESS_DENIED, selfInJob: true,
			wantProbe: true, wantBound: true},
		{name: "unreadable job, membership unknown, breakaway accepted", queryErr: windows.ERROR_ACCESS_DENIED, inJobErr: membershipUnknown, accepted: true,
			wantProbe: true, wantFlags: independentBase | windows.CREATE_BREAKAWAY_FROM_JOB, wantStarted: true},
		{name: "unreadable job, membership unknown, breakaway refused", queryErr: windows.ERROR_ACCESS_DENIED, inJobErr: membershipUnknown,
			wantProbe: true, wantBound: true},
		{name: "query refused outside any job", queryErr: windows.ERROR_ACCESS_DENIED, wantFlags: independentBase, wantStarted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started, probed := false, false
			var flags uint32
			cmd := exec.Command("child.exe")
			err := startIndependent(cmd, independentHost{
				jobLimits: func() (uint32, error) { return tc.limits, tc.queryErr },
				inJob:     func() (bool, error) { return tc.selfInJob, tc.inJobErr },
				breakawayAccepted: func(path string) bool {
					probed = true
					if path != cmd.Path {
						t.Errorf("probed %q, want the child's own path %q", path, cmd.Path)
					}
					return tc.accepted
				},
				start: func(c *exec.Cmd) error {
					flags = c.SysProcAttr.CreationFlags
					started = true
					return nil
				},
			})
			if errors.Is(err, ErrChildBoundToJob) != tc.wantBound || (!tc.wantBound && err != nil) {
				t.Fatalf("err = %v, want bound=%v", err, tc.wantBound)
			}
			if started != tc.wantStarted || probed != tc.wantProbe {
				t.Fatalf("started=%v probed=%v, want %v %v", started, probed, tc.wantStarted, tc.wantProbe)
			}
			if tc.wantFlags != 0 && flags != tc.wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, tc.wantFlags)
			}
		})
	}
}

// independentReport is what TestIndependentHelper writes for its parent.
type independentReport struct {
	QueryErr        string `json:"query_err"`
	QueryDenied     bool   `json:"query_denied"`
	InJob           bool   `json:"in_job"`
	StartErr        string `json:"start_err"`
	Bound           bool   `json:"bound"`
	PID             int    `json:"pid"`
	Grandchild      int    `json:"grandchild"`
	GrandchildInJob bool   `json:"grandchild_in_job"`
}

// TestIndependentHelper is the child and grandchild of the native tests
// below; it does nothing in a normal run.
func TestIndependentHelper(t *testing.T) {
	switch os.Getenv("DC_INDEPENDENT_HELPER") {
	case "":
		return
	case "grandchild":
		// Runs until the test drops its stop file, at most two minutes.
		stop := filepath.Join(os.Getenv("DC_INDEPENDENT_DIR"), "stop")
		for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if _, err := os.Stat(stop); err == nil {
				break
			}
		}
		os.Exit(0)
	case "job-child":
		// Wait until the parent has put this process in its job.
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			os.Exit(3)
		}
		report := independentStart()
		raw, _ := json.Marshal(report)
		fmt.Println(string(raw))
		_, _ = io.Copy(io.Discard, os.Stdin) // until the parent ends the job
		os.Exit(0)
	case "task":
		report := independentStart()
		raw, _ := json.Marshal(report)
		result := filepath.Join(os.Getenv("DC_INDEPENDENT_DIR"), "result.json")
		if err := os.WriteFile(result+".new", raw, 0o600); err != nil || os.Rename(result+".new", result) != nil {
			os.Exit(4)
		}
		time.Sleep(2 * time.Minute) // until the scheduler ends the task
		os.Exit(0)
	}
}

func independentStart() independentReport {
	report := independentReport{PID: os.Getpid()}
	if _, err := currentJobLimits(); err != nil {
		report.QueryErr = err.Error()
		report.QueryDenied = errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	report.InJob, _ = processInAnyJob(0)
	self, err := os.Executable()
	if err != nil {
		report.StartErr = err.Error()
		return report
	}
	grandchild := exec.Command(self, "-test.run=^TestIndependentHelper$")
	grandchild.Env = append(os.Environ(), "DC_INDEPENDENT_HELPER=grandchild")
	host := windowsIndependentHost
	if os.Getenv("DC_INDEPENDENT_UNREADABLE") != "" {
		// The job query a LocalSystem scheduled task is refused (GAP-0960);
		// everything else is the real host.
		host.jobLimits = func() (uint32, error) { return 0, windows.ERROR_ACCESS_DENIED }
	}
	if err := startIndependent(grandchild, host); err != nil {
		report.StartErr = err.Error()
		report.Bound = errors.Is(err, ErrChildBoundToJob)
		return report
	}
	report.Grandchild = grandchild.Process.Pid
	report.GrandchildInJob, _ = processInAnyJob(report.Grandchild)
	_ = grandchild.Process.Release()
	return report
}

func processAlive(t *testing.T, pid int) bool {
	t.Helper()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	event, err := windows.WaitForSingleObject(process, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}

func waitProcessGone(t *testing.T, pid int, limit time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(limit); processAlive(t, pid); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d did not end within %s", pid, limit)
		}
	}
}

// newSupervisorJob creates a job with limits, as a deployment agent's job.
func newSupervisorJob(t *testing.T, limits uint32) windows.Handle {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = limits
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		t.Fatal(err)
	}
	return job
}

// A recovery helper started from a kill-on-close job that allows breakaway,
// with the flag or silently, outlives the job being closed; from a readable
// one that allows none nothing starts. A job a member cannot query cannot be
// made here (the query of the caller's own job ignores the job's DACL), so
// the unreadable rows refuse only the limits query and keep the real job,
// probe and start: the child asks for CREATE_BREAKAWAY_FROM_JOB when the job
// accepts it (a job that allows only silent breakaway does, loop round 3
// review), and an unreadable job that accepts no breakaway refuses before
// anything starts. The
// scheduled-task test below is the real unreadable context.
func TestStartIndependentFromAKillOnCloseJob(t *testing.T) {
	outer, outerErr := currentJobLimits()
	selfInJob, _ := processInAnyJob(0)
	escapes := !selfInJob || (outerErr == nil && outer&(windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK|windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0)
	for _, tc := range []struct {
		name       string
		limits     uint32
		unreadable bool
		wantStart  bool
	}{
		{name: "breakaway allowed", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK, wantStart: true},
		{name: "silent breakaway", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, wantStart: true},
		{name: "breakaway refused", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
		{name: "unreadable, breakaway allowed", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
			unreadable: true, wantStart: true},
		{name: "unreadable, silent breakaway", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
			unreadable: true, wantStart: true},
		{name: "unreadable, breakaway refused", limits: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, unreadable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantStart && !escapes {
				t.Skip("the test process's own job keeps its children, so no child can leave it")
			}
			dir := t.TempDir()
			job := newSupervisorJob(t, tc.limits)
			jobOpen := true
			defer func() {
				if jobOpen {
					_ = windows.CloseHandle(job)
				}
			}()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(self, "-test.run=^TestIndependentHelper$")
			child.Env = append(os.Environ(), "DC_INDEPENDENT_HELPER=job-child", "DC_INDEPENDENT_DIR="+dir)
			if tc.unreadable {
				child.Env = append(child.Env, "DC_INDEPENDENT_UNREADABLE=1")
			}
			if escapes && selfInJob {
				child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB}
			}
			stdin, err := child.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
			process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(child.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			err = windows.AssignProcessToJobObject(job, process)
			_ = windows.CloseHandle(process)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(stdin, "GO\n"); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil {
				t.Fatalf("no report from the child in the job: %v", err)
			}
			var report independentReport
			if err := json.Unmarshal([]byte(line), &report); err != nil {
				t.Fatalf("report %q: %v", line, err)
			}
			if !report.InJob || report.QueryErr != "" {
				t.Fatalf("the child did not run in a readable job: %+v", report)
			}
			if !tc.wantStart {
				if !report.Bound || report.Grandchild != 0 {
					t.Fatalf("a job that refuses breakaway started a recovery helper: %+v", report)
				}
				return
			}
			if report.StartErr != "" || report.Grandchild == 0 || report.GrandchildInJob {
				t.Fatalf("no independent recovery helper from a kill-on-close job: %+v", report)
			}
			defer func() {
				_ = os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
				waitProcessGone(t, report.Grandchild, 10*time.Second)
			}()
			// The supervisor closes the job: its processes end, the helper stays.
			_ = windows.CloseHandle(job)
			jobOpen = false
			waitProcessGone(t, child.Process.Pid, 10*time.Second)
			if !processAlive(t, report.Grandchild) {
				t.Fatal("the recovery helper ended with the job it was started from")
			}
		})
	}
}

// The deployment context itself: the documented one-shot LocalSystem
// scheduled task (GAP-0960). Its process is refused the job query (Access
// is denied); the helper it starts must outlive the task being ended.
func TestStartIndependentFromALocalSystemScheduledTask(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("registering a LocalSystem scheduled task needs an elevated test run")
	}
	dir, err := os.MkdirTemp(os.Getenv("SystemDrive")+`\`, "dcind-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "h.exe")
	if err := os.WriteFile(helper, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.cmd")
	body := "@set DC_INDEPENDENT_HELPER=task\r\n@set \"DC_INDEPENDENT_DIR=" + dir + "\"\r\n" +
		"@\"" + helper + "\" \"-test.run=^TestIndependentHelper$\" > \"" + filepath.Join(dir, "task.log") + "\" 2>&1\r\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "DefenseClawIndependentTest-" + hex.EncodeToString(suffix)
	schtasks := func(args ...string) (string, error) {
		out, err := exec.Command("schtasks.exe", args...).CombinedOutput()
		return string(out), err
	}
	if out, err := schtasks("/Create", "/F", "/TN", name, "/RU", "SYSTEM", "/SC", "ONCE", "/ST", "00:00", "/TR", `"`+script+`"`); err != nil {
		t.Fatalf("create the scheduled task: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = schtasks("/End", "/TN", name)
		_, _ = schtasks("/Delete", "/F", "/TN", name)
	})
	if out, err := schtasks("/Run", "/TN", name); err != nil {
		t.Fatalf("run the scheduled task: %v\n%s", err, out)
	}
	var report independentReport
	result := filepath.Join(dir, "result.json")
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		if raw, err := os.ReadFile(result); err == nil {
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("report %q: %v", raw, err)
			}
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(dir, "task.log"))
			t.Fatalf("the scheduled task wrote no report within 90 s\n%s", log)
		}
	}
	t.Logf("scheduled task: %+v", report)
	if !report.QueryDenied {
		t.Logf("this host lets the scheduled task read its job; the refused query is covered by the decision test")
	}
	if report.StartErr != "" || report.Grandchild == 0 || report.GrandchildInJob {
		t.Fatalf("the LocalSystem scheduled task could not start an independent recovery helper: %+v", report)
	}
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
		waitProcessGone(t, report.Grandchild, 10*time.Second)
	}()
	if out, err := schtasks("/End", "/TN", name); err != nil {
		t.Fatalf("end the scheduled task: %v\n%s", err, out)
	}
	waitProcessGone(t, report.PID, 30*time.Second)
	if !processAlive(t, report.Grandchild) {
		t.Fatal("the recovery helper ended with the scheduled task it was started from")
	}
}
