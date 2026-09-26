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

package openshell_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

const ws = openshell.DefaultWorkspace

func newClient(t *testing.T, opts ...openshelltest.Option) (*openshelltest.Fake, openshell.Client) {
	t.Helper()
	f := openshelltest.New(opts...)
	c := f.Client(openshell.ClientOptions{})
	t.Cleanup(func() { _ = c.Close() })
	return f, c
}

func basePolicy() *openshell.SandboxPolicy {
	return &openshell.SandboxPolicy{
		Version:    1,
		Filesystem: &v1.FilesystemPolicy{ReadOnly: []string{"/usr"}, ReadWrite: []string{"/tmp", "/work/app"}},
		Landlock:   &v1.LandlockPolicy{Compatibility: "hard_requirement"},
		Process:    &v1.ProcessPolicy{RunAsUser: "1000", RunAsGroup: "1000"},
		NetworkPolicies: map[string]openshell.NetworkPolicyRule{
			"defenseclaw-egress": {Name: "defenseclaw-egress",
				Endpoints: []v1.PolicyNetworkEndpoint{{Host: "host.openshell.internal", Port: 18972, Protocol: "tcp", TLS: v1.NetworkTLSModeSkip}},
				Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}}},
		},
	}
}

func createReady(t *testing.T, c openshell.Client, name string, labels map[string]string) *openshell.Sandbox {
	t.Helper()
	ctx := context.Background()
	if _, err := c.CreateSandbox(ctx, name, &openshell.SandboxSpec{Policy: basePolicy()}, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
		t.Fatalf("CreateSandbox(%s): %v", name, err)
	}
	sb, err := c.WaitReady(ctx, name)
	if err != nil {
		t.Fatalf("WaitReady(%s): %v", name, err)
	}
	return sb
}

func TestHealthAndVersionWindow(t *testing.T) {
	for _, tc := range []struct {
		version string
		ok      bool
	}{{"0.1.1", true}, {"openshell-gateway 0.1.4", true}, {"0.2.0", false}, {"0.0.37", false}, {"fake", false}} {
		_, c := newClient(t, openshelltest.WithHealth(true, tc.version))
		h, err := c.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !h.Healthy || h.RawVersion != tc.version {
			t.Fatalf("health = %+v", h)
		}
		if err := h.CheckVersion(); (err == nil) != tc.ok {
			t.Fatalf("CheckVersion(%s) = %v, want ok=%v", tc.version, err, tc.ok)
		}
	}
}

func TestSandboxLifecycle(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()

	project := map[string]string{"io.defenseclaw/project": "abc123", "io.defenseclaw/harness": "claudecode"}
	sb := createReady(t, c, "dc-claude-app-7f3a", project)
	if sb.Status.Phase != openshell.PhaseReady {
		t.Fatalf("phase = %s", sb.Status.Phase)
	}
	createReady(t, c, "dc-codex-app-0001", map[string]string{"io.defenseclaw/project": "abc123", "io.defenseclaw/harness": "codex"})
	createReady(t, c, "other", nil)

	got, err := c.ListSandboxes(ctx, map[string]string{"io.defenseclaw/project": "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "dc-claude-app-7f3a" || got[1].Name != "dc-codex-app-0001" {
		t.Fatalf("project selector returned %v", names(got))
	}
	got, _ = c.ListSandboxes(ctx, project)
	if len(got) != 1 || got[0].Name != "dc-claude-app-7f3a" {
		t.Fatalf("two-label selector returned %v", names(got))
	}
	if all, _ := c.ListSandboxes(ctx, nil); len(all) != 3 {
		t.Fatalf("unfiltered list returned %v", names(all))
	}

	if sb, err := c.StopSandbox(ctx, "other"); err != nil || sb.Status.Phase != openshell.PhaseStopped {
		t.Fatalf("stop: %v %v", sb, err)
	}
	if _, err := c.WaitStopped(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	if sb, err := c.StartSandbox(ctx, "other"); err != nil || sb.Status.Phase != openshell.PhaseReady {
		t.Fatalf("start: %v %v", sb, err)
	}

	res, err := c.DeleteSandbox(ctx, "other")
	if err != nil || res.Outcome != v1.DeletionCompleted {
		t.Fatalf("delete: %+v %v", res, err)
	}
	if err := c.WaitDeleted(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	res, err = c.DeleteSandbox(ctx, "other")
	if err != nil || res.Outcome != v1.DeletionAlreadyAbsent {
		t.Fatalf("second delete: %+v %v", res, err)
	}
	if _, err := c.GetSandbox(ctx, "other"); !openshell.IsNotFound(err) {
		t.Fatalf("get deleted = %v", err)
	}
	if f.Calls(openshelltest.MethodDeleteSandbox) != 2 {
		t.Fatalf("delete calls = %d", f.Calls(openshelltest.MethodDeleteSandbox))
	}
}

func names(sbs []*openshell.Sandbox) []string {
	out := make([]string, len(sbs))
	for i, sb := range sbs {
		out[i] = sb.Name
	}
	return out
}

func TestNamesAndLabelsAreValidatedBeforeAnyCall(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	for _, name := range []string{"", "-rf", "Upper", "has space", "a/b", strings.Repeat("a", 64), "trailing-"} {
		if _, err := c.CreateSandbox(ctx, name, nil, openshell.CreateSandboxOptions{}); !errors.Is(err, openshell.ErrInvalidName) {
			t.Fatalf("CreateSandbox(%q) = %v", name, err)
		}
		if _, err := c.Exec(ctx, name, []string{"true"}, openshell.ExecOptions{}); !errors.Is(err, openshell.ErrInvalidName) {
			t.Fatalf("Exec(%q) = %v", name, err)
		}
	}
	for _, labels := range []map[string]string{{"a,b": "c"}, {"k": "v=w"}, {"k": "v,x=y"}, {"": "v"}} {
		if _, err := c.ListSandboxes(ctx, labels); !errors.Is(err, openshell.ErrInvalidName) {
			t.Fatalf("ListSandboxes(%v) = %v", labels, err)
		}
		if _, err := c.CreateSandbox(ctx, "ok", nil, openshell.CreateSandboxOptions{Labels: labels}); !errors.Is(err, openshell.ErrInvalidName) {
			t.Fatalf("CreateSandbox labels %v = %v", labels, err)
		}
	}
	if n := f.Calls(openshelltest.MethodCreateSandbox) + f.Calls(openshelltest.MethodListSandboxes) + f.Calls(openshelltest.MethodExec); n != 0 {
		t.Fatalf("invalid input reached the gateway %d times", n)
	}
	sel, err := openshell.LabelSelector(map[string]string{"z": "1", "io.defenseclaw/project": "abc"})
	if err != nil || sel != "io.defenseclaw/project=abc,z=1" {
		t.Fatalf("LabelSelector = %q, %v", sel, err)
	}
}

func TestWaitReadyReportsConfigurationRejection(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	if _, err := c.CreateSandbox(ctx, "bad-policy", &openshell.SandboxSpec{Policy: basePolicy()}, openshell.CreateSandboxOptions{}); err != nil {
		t.Fatal(err)
	}
	f.SetAdmission(ws, "bad-policy", types.ConfigurationAdmissionRejected, "landlock path /nope does not exist")
	_, err := c.WaitReady(ctx, "bad-policy")
	var rejected *openshell.ConfigurationRejectedError
	if !errors.As(err, &rejected) || rejected.Sandbox != "bad-policy" || !strings.Contains(rejected.Message, "/nope") {
		t.Fatalf("WaitReady = %v", err)
	}
}

func TestWaitReadyTimesOutWhileConfigurationPending(t *testing.T) {
	f, c := newClient(t)
	if _, err := c.CreateSandbox(context.Background(), "slow", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
		t.Fatal(err)
	}
	f.SetAdmission(ws, "slow", types.ConfigurationAdmissionPending, "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.WaitReady(ctx, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady = %v", err)
	}
}

func TestWaitReadyFailsWhenSandboxErrorsDuringAdmission(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	if _, err := c.CreateSandbox(ctx, "crash", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
		t.Fatal(err)
	}
	f.SetAdmission(ws, "crash", types.ConfigurationAdmissionPending, "")
	calls := 0
	f.Intercept(func(method string) error {
		if method == openshelltest.MethodGetSandbox {
			calls++
			if calls == 1 {
				_ = f.SetPhase(ws, "crash", openshell.PhaseError)
			}
		}
		return nil
	})
	if _, err := c.WaitReady(ctx, "crash"); err == nil || !strings.Contains(err.Error(), "phase Error") {
		t.Fatalf("WaitReady = %v", err)
	}
}

func TestExec(t *testing.T) {
	f, c := newClient(t)
	createReady(t, c, "box", nil)
	ctx := context.Background()

	f.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte("out:" + strings.Join(call.Command, " ")), Stderr: []byte("warn"), ExitCode: 3}
	})
	var tee bytes.Buffer
	res, err := c.Exec(ctx, "box", []string{"git", "status"}, openshell.ExecOptions{WorkDir: "/work/app", Env: map[string]string{"LANG": "C"}, Stdout: &tee})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "out:git status" || string(res.Stderr) != "warn" || res.ExitCode != 3 || res.Attempts != 1 || res.Truncated {
		t.Fatalf("result = %+v", res)
	}
	if tee.String() != "out:git status" {
		t.Fatalf("tee = %q", tee.String())
	}
	call := f.ExecCalls()[0]
	if call.WorkDir != "/work/app" || call.Env["LANG"] != "C" || !call.NoLoginShell {
		t.Fatalf("call = %+v", call)
	}

	res, err = c.Exec(ctx, "box", []string{"cat"}, openshell.ExecOptions{MaxOutputBytes: 4})
	if err != nil || string(res.Stdout) != "out:" || !res.Truncated {
		t.Fatalf("capped result = %+v, %v", res, err)
	}

	if _, err := c.Exec(ctx, "missing", []string{"true"}, openshell.ExecOptions{}); !openshell.IsNotFound(err) {
		t.Fatalf("exec in missing sandbox = %v", err)
	}
	if _, err := c.Exec(ctx, "box", nil, openshell.ExecOptions{}); err == nil {
		t.Fatal("empty argv accepted")
	}
}

func TestSandboxTimeoutArgv(t *testing.T) {
	cases := []struct {
		timeout time.Duration
		secs    string
		back    time.Duration
	}{
		{time.Minute, "60", time.Minute},
		{1500 * time.Millisecond, "1.5", 1500 * time.Millisecond},
		{20 * time.Millisecond, "0.02", 20 * time.Millisecond},
		{time.Nanosecond, "0.001", time.Millisecond},
	}
	for _, tc := range cases {
		argv := openshell.SandboxTimeoutArgv([]string{"git", "status"}, tc.timeout)
		if got := strings.Join(argv, " "); got != "timeout -k 5 "+tc.secs+" git status" {
			t.Fatalf("SandboxTimeoutArgv(%s) = %q", tc.timeout, got)
		}
		cmd, d, ok := openshell.ParseSandboxTimeoutArgv(argv)
		if !ok || d != tc.back || strings.Join(cmd, " ") != "git status" {
			t.Fatalf("ParseSandboxTimeoutArgv(%q) = %q, %s, %v", argv, cmd, d, ok)
		}
	}
	for _, argv := range [][]string{{"git", "status"}, {"timeout", "-k", "5", "10"}, {"timeout", "-k", "9", "10", "true"}, {"timeout", "-k", "5", "x", "true"}} {
		if cmd, _, ok := openshell.ParseSandboxTimeoutArgv(argv); ok || strings.Join(cmd, " ") != strings.Join(argv, " ") {
			t.Fatalf("ParseSandboxTimeoutArgv(%q) accepted", argv)
		}
	}
}

// TestExecStopsCommandsInsteadOfOverlapping is the quiet long-running
// command: an attempt that times out is stopped in the sandbox and never
// retried, so no two runs of the command overlap, even when the caller
// runs it again.
func TestExecStopsCommandsInsteadOfOverlapping(t *testing.T) {
	f, c := newClient(t)
	createReady(t, c, "box", nil)
	const timeout = 100 * time.Millisecond
	type run struct{ start, end time.Time }
	var (
		mu   sync.Mutex
		runs []run
	)
	f.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		// The command runs three timeouts long unless the sandbox stops
		// it; the fake keeps it running after its client gives up.
		const duration = 3 * timeout
		end := duration
		if call.Timeout > 0 && call.Timeout < end {
			end = call.Timeout
		}
		now := time.Now()
		mu.Lock()
		runs = append(runs, run{now, now.Add(end)})
		mu.Unlock()
		return openshelltest.ExecResponse{Duration: duration}
	})
	opts := openshell.ExecOptions{Timeout: timeout, Attempts: 3, RetryDelay: time.Millisecond}
	start := time.Now()
	_, err := c.Exec(context.Background(), "box", []string{"git", "clone", "-q", "https://example.com/r.git"}, opts)
	if !errors.Is(err, openshell.ErrExecTimeout) || !strings.Contains(err.Error(), "the sandbox stopped the command (exit status 124)") {
		t.Fatalf("Exec = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 3*timeout {
		t.Fatalf("Exec returned after %s, when the command would have finished", elapsed)
	}
	call := f.ExecCalls()[0]
	if call.Timeout != timeout || call.Argv[0] != "timeout" || strings.Join(call.Command, " ") != "git clone -q https://example.com/r.git" {
		t.Fatalf("call = %+v", call)
	}
	// The caller's own retry starts only after the first run was stopped.
	if _, err := c.Exec(context.Background(), "box", []string{"git", "clone", "-q", "https://example.com/r.git"}, opts); !errors.Is(err, openshell.ErrExecTimeout) {
		t.Fatalf("second Exec = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 2 {
		t.Fatalf("the command ran %d times, want once per Exec call", len(runs))
	}
	if runs[1].start.Before(runs[0].end) {
		t.Fatalf("runs overlap: %v", runs)
	}
}

func TestExecExitStatuses(t *testing.T) {
	const timeout = 50 * time.Millisecond
	cases := []struct {
		name     string
		resp     openshelltest.ExecResponse
		wantCode int
		wantErr  error
	}{
		{name: "fast 124 is the command's own status", resp: openshelltest.ExecResponse{ExitCode: 124}, wantCode: 124},
		{name: "killed after ignoring SIGTERM", resp: openshelltest.ExecResponse{Duration: timeout, ExitCode: 137}, wantErr: openshell.ErrExecTimeout},
		{name: "stopped at the timeout", resp: openshelltest.ExecResponse{Duration: 2 * timeout}, wantErr: openshell.ErrExecTimeout},
		{name: "missing user command", resp: openshelltest.ExecResponse{ExitCode: 127,
			Stderr: []byte("timeout: failed to run command 'nope': No such file or directory\n")}, wantCode: 127},
		{name: "image without timeout", resp: openshelltest.ExecResponse{ExitCode: 127,
			Stderr: []byte("/bin/bash: line 1: timeout: command not found\n")}, wantErr: openshell.ErrNoSandboxTimeout},
		{name: "busybox image without timeout", resp: openshelltest.ExecResponse{ExitCode: 127,
			Stderr: []byte("sh: timeout: not found\n")}, wantErr: openshell.ErrNoSandboxTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newClient(t)
			createReady(t, c, "box", nil)
			f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse { return tc.resp })
			res, err := c.Exec(context.Background(), "box", []string{"nope"}, openshell.ExecOptions{Timeout: timeout})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Exec = %+v, %v; want %v", res, err, tc.wantErr)
				}
				return
			}
			if err != nil || res.ExitCode != tc.wantCode {
				t.Fatalf("Exec = %+v, %v", res, err)
			}
		})
	}
}

func TestExecRetryPolicy(t *testing.T) {
	unavailable := &v1.StatusError{Code: v1.ErrorUnavailable, Message: "relay dropped"}
	cases := []struct {
		name     string
		opts     openshell.ExecOptions
		respond  func(attempt int) openshelltest.ExecResponse
		failNext error
		wantRuns int
		wantOpen int
		wantErr  func(error) bool
	}{
		{
			name:     "gateway hang is not retried",
			opts:     openshell.ExecOptions{Timeout: 10 * time.Millisecond, Attempts: 3, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{Hang: true} },
			wantRuns: 1,
			wantOpen: 1,
			wantErr: func(err error) bool {
				return errors.Is(err, openshell.ErrExecTimeout) && strings.Contains(err.Error(), "no exit status from the gateway")
			},
		},
		{
			name: "failure after output is not retried",
			opts: openshell.ExecOptions{Attempts: 3, RetryDelay: time.Millisecond},
			respond: func(int) openshelltest.ExecResponse {
				return openshelltest.ExecResponse{Stdout: []byte("partial"), Err: unavailable}
			},
			wantRuns: 1,
			wantOpen: 1,
			wantErr:  openshell.IsUnavailable,
		},
		{
			name:     "stream lost before output is not retried",
			opts:     openshell.ExecOptions{Attempts: 3, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{Err: unavailable} },
			wantRuns: 1,
			wantOpen: 1,
			wantErr:  openshell.IsUnavailable,
		},
		{
			name:     "stream that never opened is retried when asked",
			opts:     openshell.ExecOptions{Attempts: 3, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{Stdout: []byte("ok")} },
			failNext: unavailable,
			wantRuns: 1, // the failed open never reaches the handler
			wantOpen: 2,
		},
		{
			name:     "one attempt by default",
			opts:     openshell.ExecOptions{RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{} },
			failNext: unavailable,
			wantRuns: 0,
			wantOpen: 1,
			wantErr:  openshell.IsUnavailable,
		},
		{
			name:     "idempotent hang is retried",
			opts:     openshell.ExecOptions{Timeout: 10 * time.Millisecond, Idempotent: true, RetryDelay: time.Millisecond},
			respond:  hangOnce,
			wantRuns: 2,
			wantOpen: 2,
		},
		{
			name:     "idempotent hangs use the default attempts",
			opts:     openshell.ExecOptions{Timeout: 10 * time.Millisecond, Idempotent: true, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{Hang: true} },
			wantRuns: openshell.DefaultIdempotentExecAttempts,
			wantOpen: openshell.DefaultIdempotentExecAttempts,
			wantErr: func(err error) bool {
				return errors.Is(err, openshell.ErrExecTimeout) && strings.Contains(err.Error(), "attempt 3 of 3: ") &&
					strings.Contains(err.Error(), "no exit status from the gateway")
			},
		},
		{
			name:     "idempotent attempts are capped by Attempts",
			opts:     openshell.ExecOptions{Timeout: 10 * time.Millisecond, Idempotent: true, Attempts: 1, RetryDelay: time.Millisecond},
			respond:  hangOnce,
			wantRuns: 1,
			wantOpen: 1,
			wantErr:  func(err error) bool { return errors.Is(err, openshell.ErrExecTimeout) },
		},
		{
			name: "idempotent hang after output is not retried",
			opts: openshell.ExecOptions{Timeout: 10 * time.Millisecond, Idempotent: true, RetryDelay: time.Millisecond},
			respond: func(int) openshelltest.ExecResponse {
				return openshelltest.ExecResponse{Stdout: []byte("partial"), Hang: true}
			},
			wantRuns: 1,
			wantOpen: 1,
			wantErr:  func(err error) bool { return errors.Is(err, openshell.ErrExecTimeout) },
		},
		{
			name:     "idempotent command stopped at its timeout is not retried",
			opts:     openshell.ExecOptions{Timeout: 10 * time.Millisecond, Idempotent: true, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{Duration: time.Second} },
			wantRuns: 1,
			wantOpen: 1,
			wantErr: func(err error) bool {
				return errors.Is(err, openshell.ErrExecTimeout) && strings.Contains(err.Error(), "the sandbox stopped the command")
			},
		},
		{
			name:     "idempotent stream lost before output is not retried",
			opts:     openshell.ExecOptions{Idempotent: true, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{Err: unavailable} },
			wantRuns: 1,
			wantOpen: 1,
			wantErr:  openshell.IsUnavailable,
		},
		{
			name:     "idempotent open refusal is not retried",
			opts:     openshell.ExecOptions{Idempotent: true, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{} },
			failNext: &v1.StatusError{Code: v1.ErrorPermissionDenied, Message: "no"},
			wantRuns: 0,
			wantOpen: 1,
			wantErr:  openshell.IsPermissionDenied,
		},
		{
			name:     "open refusal is not retried",
			opts:     openshell.ExecOptions{Attempts: 3, RetryDelay: time.Millisecond},
			respond:  func(int) openshelltest.ExecResponse { return openshelltest.ExecResponse{} },
			failNext: &v1.StatusError{Code: v1.ErrorPermissionDenied, Message: "no"},
			wantRuns: 0,
			wantOpen: 1,
			wantErr:  openshell.IsPermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newClient(t)
			createReady(t, c, "box", nil)
			runs := 0
			f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
				runs++
				return tc.respond(runs)
			})
			if tc.failNext != nil {
				f.FailNext(openshelltest.MethodExec, tc.failNext)
			}
			res, err := c.Exec(context.Background(), "box", []string{"true"}, tc.opts)
			if tc.wantErr == nil && (err != nil || res.Attempts != tc.wantOpen) {
				t.Fatalf("Exec = %+v, %v", res, err)
			}
			if tc.wantErr != nil && !tc.wantErr(err) {
				t.Fatalf("Exec error = %v", err)
			}
			if runs != tc.wantRuns || f.Calls(openshelltest.MethodExec) != tc.wantOpen {
				t.Fatalf("handler ran %d times over %d opens, want %d over %d", runs, f.Calls(openshelltest.MethodExec), tc.wantRuns, tc.wantOpen)
			}
		})
	}
}

// hangOnce is the first exec after a sandbox starts in OpenShell 0.1.1:
// the stream opens and then nothing arrives; the next try answers.
func hangOnce(attempt int) openshelltest.ExecResponse {
	if attempt == 1 {
		return openshelltest.ExecResponse{Hang: true}
	}
	return openshelltest.ExecResponse{Stdout: []byte("ok\n")}
}

// TestExecRetriesUnansweredIdempotentCommands checks the retry after a
// hang: it starts only after the hung attempt's deadline, once the sandbox
// has stopped any first run, after the backoff, and the caller's writer
// sees only the answer.
func TestExecRetriesUnansweredIdempotentCommands(t *testing.T) {
	f, c := newClient(t)
	createReady(t, c, "box", nil)
	const (
		timeout = 20 * time.Millisecond
		delay   = 30 * time.Millisecond
		grace   = 250 * time.Millisecond // openshelltest's ExecGrace
	)
	var starts []time.Time
	f.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		starts = append(starts, time.Now())
		if call.Timeout != timeout {
			t.Errorf("attempt %d timeout = %s", len(starts), call.Timeout)
		}
		return hangOnce(len(starts))
	})
	var stdout bytes.Buffer
	res, err := c.Exec(context.Background(), "box", []string{"cat", "/etc/os-release"},
		openshell.ExecOptions{Timeout: timeout, Idempotent: true, RetryDelay: delay, Stdout: &stdout})
	if err != nil {
		t.Fatalf("Exec = %v", err)
	}
	if res.Attempts != 2 || string(res.Stdout) != "ok\n" || stdout.String() != "ok\n" || res.ExitCode != 0 {
		t.Fatalf("result = %+v, tee %q", res, stdout.String())
	}
	if len(starts) != 2 {
		t.Fatalf("ran %d times", len(starts))
	}
	if gap := starts[1].Sub(starts[0]); gap < timeout+grace+delay {
		t.Fatalf("retry started %s after the hung attempt, before its deadline and backoff", gap)
	}
}

func TestExecHonoursCallerCancellation(t *testing.T) {
	for _, idempotent := range []bool{false, true} {
		f, c := newClient(t)
		createReady(t, c, "box", nil)
		runs := 0
		ctx, cancel := context.WithCancel(context.Background())
		f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
			runs++
			cancel()
			return openshelltest.ExecResponse{Hang: true}
		})
		_, err := c.Exec(ctx, "box", []string{"true"}, openshell.ExecOptions{Timeout: time.Minute, Idempotent: idempotent, RetryDelay: time.Millisecond})
		if err == nil || errors.Is(err, openshell.ErrExecTimeout) || runs != 1 {
			t.Fatalf("idempotent=%v: Exec = %v after %d runs", idempotent, err, runs)
		}
	}
}

func profile(id string) openshell.ProfileImportItem {
	return openshell.ProfileImportItem{Source: id + ".yaml", Profile: openshell.ProviderProfile{
		ID: id, DisplayName: id, Category: v1.ProfileCategoryAgent,
		Credentials: []openshell.ProfileCredential{{Name: "token", EnvVars: []string{"DEFENSECLAW_SANDBOX_TOKEN"}, Required: true, Secret: true, AuthStyle: "bearer"}},
		Endpoints:   []openshell.NetworkEndpoint{{Host: "host.openshell.internal", Port: 18971, Protocol: "rest"}},
	}}
}

func TestProviderProfiles(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()

	lint, err := c.LintProfiles(ctx, []openshell.ProfileImportItem{profile("defenseclaw-ingress"), profile("Bad ID")})
	if err != nil || lint.Valid || len(lint.Diagnostics) != 1 || lint.Diagnostics[0].Field != "id" {
		t.Fatalf("lint = %+v, %v", lint, err)
	}

	res, err := c.ImportProfiles(ctx, []openshell.ProfileImportItem{profile("defenseclaw-ingress"), profile("defenseclaw-claude-code")})
	if err != nil || !res.Imported || len(res.Profiles) != 2 {
		t.Fatalf("import = %+v, %v", res, err)
	}
	if n := f.Calls(openshelltest.MethodImportProfiles); n != 2 {
		t.Fatalf("import used %d requests, want one per profile", n)
	}
	if _, err := c.ImportProfiles(ctx, []openshell.ProfileImportItem{profile("defenseclaw-ingress")}); !openshell.IsAlreadyExists(err) {
		t.Fatalf("re-import = %v", err)
	}

	got, err := c.GetProfile(ctx, "defenseclaw-ingress")
	if err != nil || got.ResourceVersion != 1 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	upd := profile("defenseclaw-ingress")
	upd.Profile.Description = "rotated"
	if _, err := c.UpdateProfile(ctx, "defenseclaw-ingress", 7, upd); !openshell.IsConflict(err) {
		t.Fatalf("stale update = %v", err)
	}
	ur, err := c.UpdateProfile(ctx, "defenseclaw-ingress", got.ResourceVersion, upd)
	if err != nil || !ur.Updated || ur.Profile.Description != "rotated" || ur.Profile.ResourceVersion != 2 {
		t.Fatalf("update = %+v, %v", ur, err)
	}
	list, err := c.ListProfiles(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if dr, err := c.DeleteProfile(ctx, "defenseclaw-claude-code"); err != nil || dr.Outcome != v1.DeletionCompleted {
		t.Fatalf("delete = %+v, %v", dr, err)
	}
	if dr, err := c.DeleteProfile(ctx, "defenseclaw-claude-code"); err != nil || dr.Outcome != v1.DeletionAlreadyAbsent {
		t.Fatalf("delete missing = %+v, %v", dr, err)
	}
}

func TestProvidersAndAttachment(t *testing.T) {
	_, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)

	p := &openshell.Provider{Name: "dc-ingress-box", Type: "defenseclaw-ingress",
		Spec: openshell.ProviderSpec{Credentials: map[string]string{"DEFENSECLAW_SANDBOX_TOKEN": "t1"}}}
	if _, err := c.CreateProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.Spec.Credentials["DEFENSECLAW_SANDBOX_TOKEN"] = "t2"
	if _, err := c.EnsureProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetProvider(ctx, "dc-ingress-box")
	if err != nil || got.Spec.Credentials["DEFENSECLAW_SANDBOX_TOKEN"] != "t2" {
		t.Fatalf("rotated provider = %+v, %v", got, err)
	}
	if _, err := c.EnsureProvider(ctx, &openshell.Provider{Name: "dc-egress-box", Type: "generic"}); err != nil {
		t.Fatal(err)
	}
	ps, err := c.ListProviders(ctx)
	if err != nil || len(ps) != 2 || ps[0].Name != "dc-egress-box" {
		t.Fatalf("list = %v, %v", ps, err)
	}

	ar, err := c.AttachProvider(ctx, "box", "dc-ingress-box")
	if err != nil || !ar.Attached {
		t.Fatalf("attach = %+v, %v", ar, err)
	}
	if ar, _ := c.AttachProvider(ctx, "box", "dc-ingress-box"); ar.Attached {
		t.Fatal("second attach reported a change")
	}
	if _, err := c.AttachProvider(ctx, "box", "missing"); !openshell.IsNotFound(err) {
		t.Fatalf("attach missing provider = %v", err)
	}
	dr, err := c.DetachProvider(ctx, "box", "dc-ingress-box")
	if err != nil || !dr.Detached {
		t.Fatalf("detach = %+v, %v", dr, err)
	}
	if res, err := c.DeleteProvider(ctx, "dc-ingress-box"); err != nil || res.Outcome != v1.DeletionCompleted {
		t.Fatalf("delete = %+v, %v", res, err)
	}
	if _, err := c.CreateProvider(ctx, &openshell.Provider{Name: "../x"}); !errors.Is(err, openshell.ErrInvalidName) {
		t.Fatalf("bad provider name = %v", err)
	}
}

func proposedRule(host string) *openshell.NetworkPolicyRule {
	return &openshell.NetworkPolicyRule{Name: "allow_" + host,
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: host, Port: 443}},
		Binaries:  []v1.PolicyNetworkBinary{{Path: "/usr/bin/curl"}}}
}

func TestDraftInbox(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)

	a := f.AddDraftChunk(ws, "box", types.PolicyChunk{RuleName: "allow_pypi", ProposedRule: proposedRule("pypi.org"), ReviewToken: "tok-a"})
	b := f.AddDraftChunk(ws, "box", types.PolicyChunk{RuleName: "allow_npm", ProposedRule: proposedRule("registry.npmjs.org")})
	d := f.AddDraftChunk(ws, "box", types.PolicyChunk{RuleName: "allow_gh", ProposedRule: proposedRule("github.com")})
	flagged := f.AddDraftChunk(ws, "box", types.PolicyChunk{RuleName: "allow_meta", ProposedRule: proposedRule("169.254.169.254"), SecurityNotes: "metadata IP"})
	bad := f.AddDraftChunk(ws, "box", types.PolicyChunk{RuleName: "allow_bin", ProposedRule: proposedRule("webhook.site")})

	draft, err := c.GetDraft(ctx, "box", "pending")
	if err != nil || len(draft.Chunks) != 5 {
		t.Fatalf("draft = %+v, %v", draft, err)
	}
	if _, err := c.ApproveDraftChunk(ctx, "box", a, "wrong"); !openshell.IsInvalidArgument(err) {
		t.Fatalf("approve with stale token = %v", err)
	}
	ar, err := c.ApproveDraftChunk(ctx, "box", a, "tok-a")
	if err != nil || ar.PolicyVersion != 2 {
		t.Fatalf("approve = %+v, %v", ar, err)
	}
	if _, err := c.ApproveDraftChunk(ctx, "box", a, "tok-a"); !openshell.IsConflict(err) {
		t.Fatalf("double approve = %v", err)
	}

	batch, err := c.ApproveDraftChunks(ctx, "box", []openshell.DraftChunkApproval{{ChunkID: b}, {ChunkID: d}, {ChunkID: flagged}})
	if err != nil || batch.ChunksApproved != 2 || batch.ChunksSkipped != 1 || batch.PolicyVersion != 3 {
		t.Fatalf("batch = %+v, %v", batch, err)
	}
	if err := c.RejectDraftChunk(ctx, "box", bad, "exfil destination"); err != nil {
		t.Fatal(err)
	}
	if chunk, _ := f.DraftChunk(ws, "box", bad); chunk.Status != "rejected" || chunk.RejectionReason != "exfil destination" {
		t.Fatalf("rejected chunk = %+v", chunk)
	}

	policy, version := f.SandboxPolicy(ws, "box")
	if version != 3 {
		t.Fatalf("policy version = %d", version)
	}
	for _, rule := range []string{"defenseclaw-egress", "allow_pypi", "allow_npm", "allow_gh"} {
		if _, ok := policy.NetworkPolicies[rule]; !ok {
			t.Fatalf("policy lacks %s: %v", rule, policy.NetworkPolicies)
		}
	}
	if _, ok := policy.NetworkPolicies["allow_meta"]; ok {
		t.Fatal("security-flagged chunk was approved")
	}
	pending, _ := c.GetDraft(ctx, "box", "pending")
	if len(pending.Chunks) != 1 || pending.Chunks[0].ID != flagged {
		t.Fatalf("pending after triage = %+v", pending.Chunks)
	}
	if empty, err := c.ApproveDraftChunks(ctx, "box", nil); err != nil || empty.ChunksApproved != 0 {
		t.Fatalf("empty batch = %+v, %v", empty, err)
	}
	if _, err := c.GetDraft(ctx, "missing", ""); !openshell.IsNotFound(err) {
		t.Fatalf("draft of missing sandbox = %v", err)
	}
}

func TestPolicyUpdates(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)

	next := basePolicy()
	next.NetworkPolicies["docs"] = *proposedRule("docs.python.org")
	res, err := c.SetPolicy(ctx, "box", next, openshell.PolicyUpdateOptions{Annotations: map[string]string{"io.defenseclaw/reason": "unblock"}})
	if err != nil || res.Version != 2 || res.PolicyHash == "" {
		t.Fatalf("set policy = %+v, %v", res, err)
	}
	static := basePolicy()
	static.Process.RunAsUser = "0"
	if _, err := c.SetPolicy(ctx, "box", static, openshell.PolicyUpdateOptions{}); !openshell.IsInvalidArgument(err) {
		t.Fatalf("static field change = %v", err)
	}

	sb, _ := c.GetSandbox(ctx, "box")
	if _, err := c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{{RemoveRule: &v1.RemoveNetworkRule{RuleName: "docs"}}},
		openshell.PolicyUpdateOptions{ExpectedResourceVersion: sb.ResourceVersion + 9}); !openshell.IsConflict(err) {
		t.Fatalf("stale merge = %v", err)
	}
	res, err = c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{
		{AddRule: &v1.AddNetworkRule{RuleName: "gh", Rule: *proposedRule("api.github.com")}},
		{RemoveRule: &v1.RemoveNetworkRule{RuleName: "docs"}},
		{AddDenyRules: &v1.AddDenyRules{
			Target:    &v1.L7RuleTarget{RuleName: "gh", Host: "api.github.com", Ports: []uint32{443}, Binaries: []v1.PolicyNetworkBinary{{Path: "/usr/bin/curl"}}},
			DenyRules: []v1.L7DenyRule{{Method: "POST", Path: "/repos/*/*/git/refs"}},
		}},
	}, openshell.PolicyUpdateOptions{ExpectedResourceVersion: sb.ResourceVersion})
	if err != nil || res.Version != 3 {
		t.Fatalf("merge = %+v, %v", res, err)
	}
	policy, _ := f.SandboxPolicy(ws, "box")
	if _, ok := policy.NetworkPolicies["docs"]; ok {
		t.Fatal("docs rule survived remove_rule")
	}
	if deny := policy.NetworkPolicies["gh"].Endpoints[0].DenyRules; len(deny) != 1 || deny[0].Method != "POST" {
		t.Fatalf("deny rules = %+v", deny)
	}
	if _, err := c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{{
		RemoveRule: &v1.RemoveNetworkRule{RuleName: "gh"}, AddRule: &v1.AddNetworkRule{RuleName: "x"},
	}}, openshell.PolicyUpdateOptions{}); err == nil || f.Calls(openshelltest.MethodUpdateConfig) != 4 {
		t.Fatalf("two-field merge op = %v (update calls %d)", err, f.Calls(openshelltest.MethodUpdateConfig))
	}

	status, err := c.PolicyStatus(ctx, "box", 0)
	if err != nil || status.Revision.Version != 3 || status.ActiveVersion != 3 {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if status, err := c.PolicyStatus(ctx, "box", 2); err != nil || status.Revision.Status != v1.PolicyLoadStatusSuperseded ||
		status.Revision.Provenance["io.defenseclaw/reason"] != "unblock" {
		t.Fatalf("revision 2 = %+v, %v", status, err)
	}
	cfg, err := c.SandboxConfig(ctx, "box")
	if err != nil || cfg.PolicyVersion != 3 || cfg.PolicySource != v1.PolicySourceSandbox {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
}

func TestGlobalPolicyDetection(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)
	if rev, err := c.GlobalPolicy(ctx); err != nil || rev != nil {
		t.Fatalf("no global policy = %+v, %v", rev, err)
	}
	f.SetGlobalPolicy(basePolicy())
	rev, err := c.GlobalPolicy(ctx)
	if err != nil || rev == nil || rev.Version != 1 {
		t.Fatalf("global policy = %+v, %v", rev, err)
	}
	if cfg, _ := c.SandboxConfig(ctx, "box"); cfg.PolicySource != v1.PolicySourceGlobal || cfg.GlobalPolicyVersion != 1 {
		t.Fatalf("config under global policy = %+v", cfg)
	}
	if _, err := c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{{RemoveRule: &v1.RemoveNetworkRule{RuleName: "defenseclaw-egress"}}}, openshell.PolicyUpdateOptions{}); !openshell.IsConflict(err) {
		t.Fatalf("merge under global lock = %v", err)
	}
	f.SetGlobalPolicy(nil)
	if rev, err := c.GlobalPolicy(ctx); err != nil || rev != nil {
		t.Fatalf("cleared global policy = %+v, %v", rev, err)
	}
}

func TestUpdateSetting(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)
	val := &openshell.SettingValue{Type: openshell.SettingBool, BoolVal: false}

	for _, bad := range []openshell.SettingUpdate{
		{Sandbox: "box", Value: val},
		{Key: "k", Value: val},
		{Key: "k", Sandbox: "box", Global: true, Value: val},
		{Key: "k", Sandbox: "box"},
		{Key: "k", Sandbox: "box", Value: val, Delete: true},
		{Key: "k", Sandbox: "box", Delete: true},
		{Key: "k", Sandbox: "Bad Name", Value: val},
	} {
		if _, err := c.UpdateSetting(ctx, bad); err == nil {
			t.Fatalf("UpdateSetting(%+v) accepted", bad)
		}
	}
	if n := f.Calls(openshelltest.MethodUpdateConfig); n != 0 {
		t.Fatalf("invalid updates reached the gateway %d times", n)
	}

	if _, err := c.UpdateSetting(ctx, openshell.SettingUpdate{Sandbox: "box", Key: "ocsf_json_enabled", Value: &openshell.SettingValue{Type: openshell.SettingBool, BoolVal: true}}); err != nil {
		t.Fatal(err)
	}
	if got := f.SandboxSettings(ws, "box")["ocsf_json_enabled"]; !got.BoolVal {
		t.Fatalf("sandbox setting = %+v", got)
	}
	if _, err := c.UpdateSetting(ctx, openshell.SettingUpdate{Global: true, Key: "telemetry", Value: val}); err != nil {
		t.Fatal(err)
	}
	gw, err := c.GatewaySettings(ctx)
	if err != nil || gw.SettingsRevision != 1 {
		t.Fatalf("gateway settings = %+v, %v", gw, err)
	}
	res, err := c.UpdateSetting(ctx, openshell.SettingUpdate{Global: true, Key: "telemetry", Delete: true})
	if err != nil || !res.Deleted {
		t.Fatalf("global delete = %+v, %v", res, err)
	}
	cfg, _ := c.SandboxConfig(ctx, "box")
	if s, ok := cfg.Settings["ocsf_json_enabled"]; !ok || s.Scope != v1.SettingScopeSandbox {
		t.Fatalf("effective settings = %+v", cfg.Settings)
	}
}

// deadlineRecorder wraps the fake so a test can observe the context the
// client hands to the SDK.
type deadlineRecorder struct {
	*openshelltest.Fake
	deadline chan time.Duration
}

type recordingHealth struct {
	v1.HealthInterface
	deadline chan time.Duration
}

func (r deadlineRecorder) Health() v1.HealthInterface {
	return recordingHealth{HealthInterface: r.Fake.Health(), deadline: r.deadline}
}

func (h recordingHealth) Check(ctx context.Context) (*v1.HealthResult, error) {
	d, ok := ctx.Deadline()
	if !ok {
		h.deadline <- 0
	} else {
		h.deadline <- time.Until(d)
	}
	return h.HealthInterface.Check(ctx)
}

func TestRPCTimeoutAppliedOnlyWithoutDeadline(t *testing.T) {
	rec := deadlineRecorder{Fake: openshelltest.New(), deadline: make(chan time.Duration, 2)}
	c := openshell.NewClient(rec, openshell.ClientOptions{RPCTimeout: 7 * time.Second})
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := <-rec.deadline; d <= 6*time.Second || d > 7*time.Second {
		t.Fatalf("default deadline = %s", d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if _, err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if d := <-rec.deadline; d < 59*time.Minute {
		t.Fatalf("caller deadline replaced: %s", d)
	}
	if c.Workspace() != openshell.DefaultWorkspace {
		t.Fatalf("workspace = %q", c.Workspace())
	}
}

func TestClosedClientFailsUnavailable(t *testing.T) {
	f, c := newClient(t)
	_ = f.Close()
	if _, err := c.Health(context.Background()); !openshell.IsUnavailable(err) {
		t.Fatalf("health after close = %v", err)
	}
	if _, err := c.ListSandboxes(context.Background(), nil); !openshell.IsUnavailable(err) {
		t.Fatalf("list after close = %v", err)
	}
}
