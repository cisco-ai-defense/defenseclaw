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

package manager

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A stop tore the sandbox down under the running harness: no SessionEnd
// hook, and "exec relay closed before the command reported an exit status"
// in the harness's terminal. The harness is asked to exit first, before
// OpenShell is asked to stop the sandbox; a sandbox that does not answer
// is stopped anyway.
func TestStopEndsTheHarnessFirst(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "stopbox"})
	e.watch.waitStarted(t, sb.Name)
	var mu sync.Mutex
	var order []string
	e.fake.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		mu.Lock()
		order = append(order, "exec")
		mu.Unlock()
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	})
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodStopSandbox {
			mu.Lock()
			order = append(order, "stop")
			mu.Unlock()
		}
		return nil
	})
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := slices.Clone(order)
	mu.Unlock()
	if len(got) < 2 || got[0] != "exec" || !slices.Contains(got, "stop") {
		t.Fatalf("calls = %v, want the harness asked to exit before the stop", got)
	}
	calls := e.fake.ExecCalls()
	if len(calls) != 1 || !slices.Contains(calls[0].Command, harness.ClaudeCode.InstallRoot()) || calls[0].Timeout <= harnessExitWait {
		t.Fatalf("exec calls = %+v", calls)
	}

	// A stopped sandbox has no harness to end; a failing exec does not keep
	// the next stop from happening.
	if _, err := e.m.Start(context.Background(), sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	e.fake.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Err: errors.New("exec relay closed")}
	})
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatalf("stop with a failing exec: %v", err)
	}
	if got, _ := e.m.Get(context.Background(), sb.Name); got.Phase != strings.ToLower(string(openshell.PhaseStopped)) {
		t.Fatalf("phase = %s", got.Phase)
	}
	before := len(e.fake.ExecCalls())
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	if n := len(e.fake.ExecCalls()); n != before {
		t.Fatalf("a stopped sandbox's harness was asked to exit (%d exec calls, want %d)", n, before)
	}
}

// The script finds the harness by the install root its executable lies
// under, sends it SIGTERM and waits for it to exit; other processes are
// left alone.
func TestEndHarnessScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the script reads /proc")
	}
	root := filepath.Join(t.TempDir(), "harness")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep(1)")
	}
	data, err := os.ReadFile(sleepBin)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin", "fakeharness")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	h := exec.Command(bin, "60")
	other := exec.Command(sleepBin, "60")
	for _, c := range []*exec.Cmd{h, other} {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	exited := make(chan struct{})
	go func() { _ = h.Wait(); close(exited) }()

	out, err := exec.Command("/bin/sh", "-c", endHarnessScript, "defenseclaw-end-harness", root, "50").Output()
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if strings.TrimSpace(string(out)) != "exited" {
		t.Fatalf("script said %q", out)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the harness did not exit")
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(other.Process.Pid))); err != nil {
		t.Fatal("another process was signalled")
	}
	out, err = exec.Command("/bin/sh", "-c", endHarnessScript, "defenseclaw-end-harness", root, "5").Output()
	if err != nil || strings.TrimSpace(string(out)) != "none" {
		t.Fatalf("script with no harness = %q, %v", out, err)
	}
}
