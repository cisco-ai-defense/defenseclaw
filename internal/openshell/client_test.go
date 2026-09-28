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
		if err != nil || !h.Healthy || h.RawVersion != tc.version {
			t.Fatalf("health = %+v, %v", h, err)
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
	if sb := createReady(t, c, "dc-claude-app-7f3a", project); sb.Status.Phase != openshell.PhaseReady {
		t.Fatalf("phase = %s", sb.Status.Phase)
	}
	createReady(t, c, "dc-codex-app-0001", map[string]string{"io.defenseclaw/project": "abc123", "io.defenseclaw/harness": "codex"})
	createReady(t, c, "other", nil)
	for _, tc := range []struct {
		selector map[string]string
		want     string
	}{
		{map[string]string{"io.defenseclaw/project": "abc123"}, "dc-claude-app-7f3a,dc-codex-app-0001"},
		{project, "dc-claude-app-7f3a"},
		{nil, "dc-claude-app-7f3a,dc-codex-app-0001,other"},
	} {
		got, err := c.ListSandboxes(ctx, tc.selector)
		var names []string
		for _, sb := range got {
			names = append(names, sb.Name)
		}
		if err != nil || strings.Join(names, ",") != tc.want {
			t.Fatalf("ListSandboxes(%v) = %v, %v", tc.selector, names, err)
		}
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
	if res, err := c.DeleteSandbox(ctx, "other"); err != nil || res.Outcome != v1.DeletionCompleted {
		t.Fatalf("delete: %+v %v", res, err)
	}
	if err := c.WaitDeleted(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	if res, err := c.DeleteSandbox(ctx, "other"); err != nil || res.Outcome != v1.DeletionAlreadyAbsent {
		t.Fatalf("second delete: %+v %v", res, err)
	}
	if _, err := c.GetSandbox(ctx, "other"); !openshell.IsNotFound(err) || f.Calls(openshelltest.MethodDeleteSandbox) != 2 {
		t.Fatalf("get deleted = %v", err)
	}
}

// TestSandboxNamesAndLabels checks that invalid names and labels never
// reach the gateway, and that new sandbox names fit OpenShell 0.1.1's 19
// characters ("name exceeds maximum length (20 > 19)", measured on the
// host) while existing sandboxes are addressed by any DNS label.
func TestSandboxNamesAndLabels(t *testing.T) {
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
	if sel, err := openshell.LabelSelector(map[string]string{"z": "1", "io.defenseclaw/project": "abc"}); err != nil || sel != "io.defenseclaw/project=abc,z=1" {
		t.Fatalf("LabelSelector = %q, %v", sel, err)
	}

	for name, want := range map[string]bool{
		"m1-calc-7500": true, strings.Repeat("a", 19): true, strings.Repeat("a", 20): false, "dc-claude-m1-calc-7500": false, "Upper": false,
	} {
		if got := openshell.ValidNewSandboxName(name); got != want {
			t.Errorf("ValidNewSandboxName(%q) = %t, want %t", name, got, want)
		}
	}
	if !openshell.ValidSandboxName(strings.Repeat("a", 63)) {
		t.Error("a 63-character sandbox must stay addressable")
	}
}

// TestWaits covers configuration admission and a gateway that restarts
// during a wait (a configuration change, doctor --fix, Restart=on-failure):
// polls that find it unreachable, or time out, are retried until the wait's
// deadline, while other failures still end the wait at once.
func TestWaits(t *testing.T) {
	ctx := context.Background()
	unavailable := &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"}
	created := func(t *testing.T, ready bool) (*openshelltest.Fake, openshell.Client) {
		f, c := newClient(t)
		if ready {
			createReady(t, c, "box", nil)
		} else if _, err := c.CreateSandbox(ctx, "box", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
			t.Fatal(err)
		}
		return f, c
	}

	t.Run("configuration rejected", func(t *testing.T) {
		f, c := created(t, false)
		f.SetAdmission(ws, "box", types.ConfigurationAdmissionRejected, "landlock path /nope does not exist")
		_, err := c.WaitReady(ctx, "box")
		var rejected *openshell.ConfigurationRejectedError
		if !errors.As(err, &rejected) || rejected.Sandbox != "box" || !strings.Contains(rejected.Message, "/nope") {
			t.Fatalf("WaitReady = %v", err)
		}
	})
	t.Run("configuration pending outlasts the wait", func(t *testing.T) {
		f, c := created(t, false)
		f.SetAdmission(ws, "box", types.ConfigurationAdmissionPending, "")
		wctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := c.WaitReady(wctx, "box"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("WaitReady = %v", err)
		}
	})
	t.Run("sandbox fails while configuration pending", func(t *testing.T) {
		f, c := created(t, false)
		f.SetAdmission(ws, "box", types.ConfigurationAdmissionPending, "")
		calls := 0
		f.Intercept(func(method string) error {
			if method != openshelltest.MethodGetSandbox {
				return nil
			}
			if calls++; calls == 1 {
				return unavailable
			}
			_ = f.SetPhase(ws, "box", openshell.PhaseError)
			return nil
		})
		// The poll after the outage sees the sandbox fail.
		if _, err := c.WaitReady(ctx, "box"); err == nil || !strings.Contains(err.Error(), "phase Error") {
			t.Fatalf("WaitReady = %v", err)
		}
	})
	t.Run("ready", func(t *testing.T) {
		f, c := created(t, false)
		f.FailNext(openshelltest.MethodWaitReady, unavailable)
		f.FailNext(openshelltest.MethodWaitReady, &v1.StatusError{Code: v1.ErrorDeadlineExceeded, Message: "poll timed out"})
		if sb, err := c.WaitReady(ctx, "box"); err != nil || sb.Status.Phase != openshell.PhaseReady || f.Calls(openshelltest.MethodWaitReady) != 3 {
			t.Fatalf("WaitReady = %v, %v after %d polls", sb, err, f.Calls(openshelltest.MethodWaitReady))
		}
	})
	t.Run("stopped", func(t *testing.T) {
		f, c := created(t, true)
		if _, err := c.StopSandbox(ctx, "box"); err != nil {
			t.Fatal(err)
		}
		f.FailNext(openshelltest.MethodWaitStopped, unavailable)
		if _, err := c.WaitStopped(ctx, "box"); err != nil {
			t.Fatalf("WaitStopped = %v", err)
		}
	})
	t.Run("deleted", func(t *testing.T) {
		f, c := created(t, true)
		if _, err := c.DeleteSandbox(ctx, "box"); err != nil {
			t.Fatal(err)
		}
		f.FailNext(openshelltest.MethodGetSandbox, unavailable)
		f.FailNext(openshelltest.MethodGetSandbox, unavailable)
		if err := c.WaitDeleted(ctx, "box"); err != nil || f.Calls(openshelltest.MethodGetSandbox) != 3 {
			t.Fatalf("WaitDeleted = %v after %d polls", err, f.Calls(openshelltest.MethodGetSandbox))
		}
	})
	t.Run("other failures end the wait", func(t *testing.T) {
		f, c := created(t, true)
		f.FailNext(openshelltest.MethodGetSandbox, &v1.StatusError{Code: v1.ErrorPermissionDenied, Message: "denied"})
		if err := c.WaitDeleted(ctx, "box"); !openshell.IsPermissionDenied(err) || f.Calls(openshelltest.MethodGetSandbox) != 1 {
			t.Fatalf("WaitDeleted = %v after %d polls", err, f.Calls(openshelltest.MethodGetSandbox))
		}
	})
	t.Run("outage outlasts the wait", func(t *testing.T) {
		f, c := created(t, false)
		f.Intercept(func(method string) error {
			if method == openshelltest.MethodWaitReady {
				return unavailable
			}
			return nil
		})
		wctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if _, err := c.WaitReady(wctx, "box"); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("WaitReady = %v", err)
		}
	})
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
	if err != nil || string(res.Stdout) != "out:git status" || string(res.Stderr) != "warn" || res.ExitCode != 3 || res.Attempts != 1 || res.Truncated {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if call := f.ExecCalls()[0]; tee.String() != "out:git status" || call.WorkDir != "/work/app" || call.Env["LANG"] != "C" || !call.NoLoginShell {
		t.Fatalf("tee = %q, call = %+v", tee.String(), call)
	}
	if res, err := c.Exec(ctx, "box", []string{"cat"}, openshell.ExecOptions{MaxOutputBytes: 4}); err != nil || string(res.Stdout) != "out:" || !res.Truncated {
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
	for _, tc := range []struct {
		timeout time.Duration
		secs    string
		back    time.Duration
	}{
		{time.Minute, "60", time.Minute},
		{1500 * time.Millisecond, "1.5", 1500 * time.Millisecond},
		{20 * time.Millisecond, "0.02", 20 * time.Millisecond},
		{time.Nanosecond, "0.001", time.Millisecond},
	} {
		argv := openshell.SandboxTimeoutArgv([]string{"git", "status"}, tc.timeout)
		if got := strings.Join(argv, " "); got != "timeout -k 5 "+tc.secs+" git status" {
			t.Fatalf("SandboxTimeoutArgv(%s) = %q", tc.timeout, got)
		}
		if cmd, d, ok := openshell.ParseSandboxTimeoutArgv(argv); !ok || d != tc.back || strings.Join(cmd, " ") != "git status" {
			t.Fatalf("ParseSandboxTimeoutArgv(%q) = %q, %s, %v", argv, cmd, d, ok)
		}
	}
	for _, argv := range [][]string{{"git", "status"}, {"timeout", "-k", "5", "10"}, {"timeout", "-k", "9", "10", "true"}, {"timeout", "-k", "5", "x", "true"}} {
		if cmd, _, ok := openshell.ParseSandboxTimeoutArgv(argv); ok || strings.Join(cmd, " ") != strings.Join(argv, " ") {
			t.Fatalf("ParseSandboxTimeoutArgv(%q) accepted", argv)
		}
	}
}

func TestSandboxExitError(t *testing.T) {
	const limit = 10 * time.Second
	for _, tc := range []struct {
		status  int
		stderr  string
		elapsed time.Duration
		want    error
	}{
		{124, "", limit, openshell.ErrExecTimeout},
		{137, "", limit + time.Second, openshell.ErrExecTimeout},
		// The command's own 124 before the deadline is an answer.
		{124, "", time.Second, nil},
		{127, "sh: 1: timeout: not found", 0, openshell.ErrNoSandboxTimeout},
		{127, "sh: timeout: not found\n", 0, openshell.ErrNoSandboxTimeout},
		{127, "timeout: failed to run command 'nope': No such file or directory", 0, nil},
		{0, "", limit, nil},
		{1, "", limit, nil},
	} {
		err := openshell.SandboxExitError(tc.status, []byte(tc.stderr), tc.elapsed, limit)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("SandboxExitError(%d, %q, %s) = %v, want %v", tc.status, tc.stderr, tc.elapsed, err, tc.want)
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
	argv := []string{"git", "clone", "-q", "https://example.com/r.git"}
	opts := openshell.ExecOptions{Timeout: timeout, Attempts: 3, RetryDelay: time.Millisecond}
	start := time.Now()
	_, err := c.Exec(context.Background(), "box", argv, opts)
	if !errors.Is(err, openshell.ErrExecTimeout) || !strings.Contains(err.Error(), "the sandbox stopped the command (exit status 124)") {
		t.Fatalf("Exec = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 3*timeout {
		t.Fatalf("Exec returned after %s, when the command would have finished", elapsed)
	}
	if call := f.ExecCalls()[0]; call.Timeout != timeout || call.Argv[0] != "timeout" || strings.Join(call.Command, " ") != strings.Join(argv, " ") {
		t.Fatalf("call = %+v", call)
	}
	// The caller's own retry starts only after the first run was stopped.
	if _, err := c.Exec(context.Background(), "box", argv, opts); !errors.Is(err, openshell.ErrExecTimeout) {
		t.Fatalf("second Exec = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 2 || runs[1].start.Before(runs[0].end) {
		t.Fatalf("runs = %v, want one per Exec call without overlap", runs)
	}
}

func TestExecExitStatuses(t *testing.T) {
	const timeout = 50 * time.Millisecond
	for _, tc := range []struct {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newClient(t)
			createReady(t, c, "box", nil)
			f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse { return tc.resp })
			res, err := c.Exec(context.Background(), "box", []string{"nope"}, openshell.ExecOptions{Timeout: timeout})
			if (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || (tc.wantErr == nil && (err != nil || res.ExitCode != tc.wantCode)) {
				t.Fatalf("Exec = %+v, %v; want code %d, error %v", res, err, tc.wantCode, tc.wantErr)
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

func TestExecRetryPolicy(t *testing.T) {
	unavailable := &v1.StatusError{Code: v1.ErrorUnavailable, Message: "relay dropped"}
	refused := &v1.StatusError{Code: v1.ErrorPermissionDenied, Message: "no"}
	answer := func(r openshelltest.ExecResponse) func(int) openshelltest.ExecResponse {
		return func(int) openshelltest.ExecResponse { return r }
	}
	timedOut := func(details ...string) func(error) bool {
		return func(err error) bool {
			for _, d := range details {
				if err == nil || !strings.Contains(err.Error(), d) {
					return false
				}
			}
			return errors.Is(err, openshell.ErrExecTimeout)
		}
	}
	const hang = 10 * time.Millisecond
	cases := []struct {
		name               string
		opts               openshell.ExecOptions
		respond            func(attempt int) openshelltest.ExecResponse
		failNext           error
		wantRuns, wantOpen int
		wantErr            func(error) bool // nil: success
	}{
		{"gateway hang is not retried", openshell.ExecOptions{Timeout: hang, Attempts: 3},
			answer(openshelltest.ExecResponse{Hang: true}), nil, 1, 1, timedOut("no exit status from the gateway")},
		{"failure after output is not retried", openshell.ExecOptions{Attempts: 3},
			answer(openshelltest.ExecResponse{Stdout: []byte("partial"), Err: unavailable}), nil, 1, 1, openshell.IsUnavailable},
		{"stream lost before output is not retried", openshell.ExecOptions{Attempts: 3},
			answer(openshelltest.ExecResponse{Err: unavailable}), nil, 1, 1, openshell.IsUnavailable},
		// The failed open never reaches the handler.
		{"stream that never opened is retried when asked", openshell.ExecOptions{Attempts: 3},
			answer(openshelltest.ExecResponse{Stdout: []byte("ok")}), unavailable, 1, 2, nil},
		{"one attempt by default", openshell.ExecOptions{}, answer(openshelltest.ExecResponse{}), unavailable, 0, 1, openshell.IsUnavailable},
		{"open refusal is not retried", openshell.ExecOptions{Attempts: 3}, answer(openshelltest.ExecResponse{}), refused, 0, 1, openshell.IsPermissionDenied},
		{"idempotent hang is retried", openshell.ExecOptions{Timeout: hang, Idempotent: true}, hangOnce, nil, 2, 2, nil},
		{"idempotent hangs use the default attempts", openshell.ExecOptions{Timeout: hang, Idempotent: true},
			answer(openshelltest.ExecResponse{Hang: true}), nil, openshell.DefaultIdempotentExecAttempts, openshell.DefaultIdempotentExecAttempts,
			timedOut("attempt 3 of 3: ", "no exit status from the gateway")},
		{"idempotent attempts are capped by Attempts", openshell.ExecOptions{Timeout: hang, Idempotent: true, Attempts: 1}, hangOnce, nil, 1, 1, timedOut()},
		{"idempotent hang after output is not retried", openshell.ExecOptions{Timeout: hang, Idempotent: true},
			answer(openshelltest.ExecResponse{Stdout: []byte("partial"), Hang: true}), nil, 1, 1, timedOut()},
		{"idempotent command stopped at its timeout is not retried", openshell.ExecOptions{Timeout: hang, Idempotent: true},
			answer(openshelltest.ExecResponse{Duration: time.Second}), nil, 1, 1, timedOut("the sandbox stopped the command")},
		{"idempotent stream lost before output is not retried", openshell.ExecOptions{Idempotent: true},
			answer(openshelltest.ExecResponse{Err: unavailable}), nil, 1, 1, openshell.IsUnavailable},
		{"idempotent open refusal is not retried", openshell.ExecOptions{Idempotent: true},
			answer(openshelltest.ExecResponse{}), refused, 0, 1, openshell.IsPermissionDenied},
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
			tc.opts.RetryDelay = time.Millisecond
			res, err := c.Exec(context.Background(), "box", []string{"true"}, tc.opts)
			if (tc.wantErr == nil && (err != nil || res.Attempts != tc.wantOpen)) || (tc.wantErr != nil && !tc.wantErr(err)) {
				t.Fatalf("Exec = %+v, %v", res, err)
			}
			if runs != tc.wantRuns || f.Calls(openshelltest.MethodExec) != tc.wantOpen {
				t.Fatalf("handler ran %d times over %d opens, want %d over %d", runs, f.Calls(openshelltest.MethodExec), tc.wantRuns, tc.wantOpen)
			}
		})
	}
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
	// The attempt's deadline starts in the client, a little before the
	// fake sees the call, so measure the retry from the Exec call.
	begin := time.Now()
	res, err := c.Exec(context.Background(), "box", []string{"cat", "/etc/os-release"},
		openshell.ExecOptions{Timeout: timeout, Idempotent: true, RetryDelay: delay, Stdout: &stdout})
	if err != nil || res.Attempts != 2 || string(res.Stdout) != "ok\n" || stdout.String() != "ok\n" || res.ExitCode != 0 || len(starts) != 2 {
		t.Fatalf("Exec = %+v, %v; tee %q after %d runs", res, err, stdout.String(), len(starts))
	}
	if gap := starts[1].Sub(begin); gap < timeout+grace+delay {
		t.Fatalf("retry started %s after Exec, before the first deadline and backoff", gap)
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
	if lint, err := c.LintProfiles(ctx, []openshell.ProfileImportItem{profile("defenseclaw-ingress"), profile("Bad ID")}); err != nil ||
		lint.Valid || len(lint.Diagnostics) != 1 || lint.Diagnostics[0].Field != "id" {
		t.Fatalf("lint = %+v, %v", lint, err)
	}
	res, err := c.ImportProfiles(ctx, []openshell.ProfileImportItem{profile("defenseclaw-ingress"), profile("defenseclaw-claude-code")})
	if err != nil || !res.Imported || len(res.Profiles) != 2 || f.Calls(openshelltest.MethodImportProfiles) != 2 {
		t.Fatalf("import = %+v, %v; want one request per profile", res, err)
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
	if ur, err := c.UpdateProfile(ctx, "defenseclaw-ingress", got.ResourceVersion, upd); err != nil || !ur.Updated || ur.Profile.ResourceVersion != 2 {
		t.Fatalf("update = %+v, %v", ur, err)
	}
	if list, err := c.ListProfiles(ctx); err != nil || len(list) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if dr, err := c.DeleteProfile(ctx, "defenseclaw-claude-code"); err != nil || dr.Outcome != v1.DeletionCompleted {
		t.Fatalf("delete = %+v, %v", dr, err)
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
	// EnsureProvider rotates an existing provider and creates a missing one.
	p.Spec.Credentials["DEFENSECLAW_SANDBOX_TOKEN"] = "t2"
	if _, err := c.EnsureProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, err := c.GetProvider(ctx, "dc-ingress-box"); err != nil || got.Spec.Credentials["DEFENSECLAW_SANDBOX_TOKEN"] != "t2" {
		t.Fatalf("rotated provider = %+v, %v", got, err)
	}
	if _, err := c.EnsureProvider(ctx, &openshell.Provider{Name: "dc-egress-box", Type: "generic"}); err != nil {
		t.Fatal(err)
	}
	if ps, err := c.ListProviders(ctx); err != nil || len(ps) != 2 || ps[0].Name != "dc-egress-box" {
		t.Fatalf("list = %v, %v", ps, err)
	}
	if ar, err := c.AttachProvider(ctx, "box", "dc-ingress-box"); err != nil || !ar.Attached {
		t.Fatalf("attach = %+v, %v", ar, err)
	}
	if ar, _ := c.AttachProvider(ctx, "box", "dc-ingress-box"); ar.Attached {
		t.Fatal("second attach reported a change")
	}
	if _, err := c.AttachProvider(ctx, "box", "missing"); !openshell.IsNotFound(err) {
		t.Fatalf("attach missing provider = %v", err)
	}
	if dr, err := c.DetachProvider(ctx, "box", "dc-ingress-box"); err != nil || !dr.Detached {
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

// TestDraftInbox covers review tokens bound to the live policy, as
// OpenShell 0.1.1 binds them: once another change lands, the single
// approval answers Conflict and the bulk approval skips the chunk.
func TestDraftInbox(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)
	chunk := func(rule, host, token, notes string) string {
		return f.AddDraftChunk(ws, "box", types.PolicyChunk{RuleName: rule, ProposedRule: proposedRule(host), ReviewToken: token, SecurityNotes: notes})
	}
	a := chunk("allow_pypi", "pypi.org", "tok-a", "")
	b := chunk("allow_npm", "registry.npmjs.org", "", "")
	flagged := chunk("allow_meta", "169.254.169.254", "", "metadata IP")
	bad := chunk("allow_bin", "webhook.site", "", "")
	if draft, err := c.GetDraft(ctx, "box", "pending"); err != nil || len(draft.Chunks) != 4 {
		t.Fatalf("draft = %+v, %v", draft, err)
	}
	if _, err := c.ApproveDraftChunk(ctx, "box", a, "wrong"); !openshell.IsConflict(err) {
		t.Fatalf("approve with a wrong token = %v", err)
	}
	late := chunk("allow_late", "late.example.org", "tok-late", "")
	if ar, err := c.ApproveDraftChunk(ctx, "box", a, "tok-a"); err != nil || ar.PolicyVersion != 2 {
		t.Fatalf("approve = %+v, %v", ar, err)
	}
	if _, err := c.ApproveDraftChunk(ctx, "box", a, "tok-a"); !openshell.IsConflict(err) {
		t.Fatalf("double approve = %v", err)
	}
	// The policy changed, so the token read before is stale: the single
	// call refuses it and the bulk call skips the chunk without an error.
	if _, err := c.ApproveDraftChunk(ctx, "box", late, "tok-late"); !openshell.IsConflict(err) {
		t.Fatalf("approve with a stale token = %v", err)
	}
	if res, err := c.ApproveDraftChunks(ctx, "box", []openshell.DraftChunkApproval{{ChunkID: late, ReviewToken: "tok-late"}}); err != nil ||
		res.ChunksApproved != 0 || res.ChunksSkipped != 1 {
		t.Fatalf("bulk approve with a stale token = %+v, %v", res, err)
	}
	if fresh, _ := f.DraftChunk(ws, "box", late); fresh.ReviewToken == "tok-late" {
		t.Fatal("the review token did not change with the policy")
	}

	batch, err := c.ApproveDraftChunks(ctx, "box", []openshell.DraftChunkApproval{{ChunkID: b}, {ChunkID: flagged}})
	if err != nil || batch.ChunksApproved != 1 || batch.ChunksSkipped != 1 || batch.PolicyVersion != 3 {
		t.Fatalf("batch = %+v, %v", batch, err)
	}
	if err := c.RejectDraftChunk(ctx, "box", bad, "exfil destination"); err != nil {
		t.Fatal(err)
	}
	if chunk, _ := f.DraftChunk(ws, "box", bad); chunk.Status != "rejected" || chunk.RejectionReason != "exfil destination" {
		t.Fatalf("rejected chunk = %+v", chunk)
	}
	policy, _ := f.SandboxPolicy(ws, "box")
	if _, ok := policy.NetworkPolicies["allow_npm"]; !ok {
		t.Fatalf("policy lacks allow_npm: %v", policy.NetworkPolicies)
	}
	if _, ok := policy.NetworkPolicies["allow_meta"]; ok {
		t.Fatal("security-flagged chunk was approved")
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
	if res, err := c.SetPolicy(ctx, "box", next, openshell.PolicyUpdateOptions{Annotations: map[string]string{"io.defenseclaw/reason": "unblock"}}); err != nil ||
		res.Version != 2 || res.PolicyHash == "" {
		t.Fatalf("set policy = %+v, %v", res, err)
	}
	static := basePolicy()
	static.Process.RunAsUser = "0"
	if _, err := c.SetPolicy(ctx, "box", static, openshell.PolicyUpdateOptions{}); !openshell.IsInvalidArgument(err) {
		t.Fatalf("static field change = %v", err)
	}

	sb, _ := c.GetSandbox(ctx, "box")
	remove := openshell.PolicyMergeOperation{RemoveRule: &v1.RemoveNetworkRule{RuleName: "docs"}}
	if _, err := c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{remove}, openshell.PolicyUpdateOptions{ExpectedResourceVersion: sb.ResourceVersion + 9}); !openshell.IsConflict(err) {
		t.Fatalf("stale merge = %v", err)
	}
	res, err := c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{
		{AddRule: &v1.AddNetworkRule{RuleName: "gh", Rule: *proposedRule("api.github.com")}},
		remove,
		{AddDenyRules: &v1.AddDenyRules{
			Target:    &v1.L7RuleTarget{RuleName: "gh", Host: "api.github.com", Ports: []uint32{443}, Binaries: []v1.PolicyNetworkBinary{{Path: "/usr/bin/curl"}}},
			DenyRules: []v1.L7DenyRule{{Method: "POST", Path: "/repos/*/*/git/refs"}},
		}},
	}, openshell.PolicyUpdateOptions{ExpectedResourceVersion: sb.ResourceVersion})
	if err != nil || res.Version != 3 {
		t.Fatalf("merge = %+v, %v", res, err)
	}
	policy, _ := f.SandboxPolicy(ws, "box")
	if deny := policy.NetworkPolicies["gh"].Endpoints[0].DenyRules; len(deny) != 1 || deny[0].Method != "POST" || policy.NetworkPolicies["docs"].Name != "" {
		t.Fatalf("merged policy = %+v", policy.NetworkPolicies)
	}
	// An operation setting two fields is refused before any call.
	if _, err := c.MergePolicy(ctx, "box", []openshell.PolicyMergeOperation{{
		RemoveRule: &v1.RemoveNetworkRule{RuleName: "gh"}, AddRule: &v1.AddNetworkRule{RuleName: "x"},
	}}, openshell.PolicyUpdateOptions{}); err == nil || f.Calls(openshelltest.MethodUpdateConfig) != 4 {
		t.Fatalf("two-field merge op = %v (update calls %d)", err, f.Calls(openshelltest.MethodUpdateConfig))
	}

	if status, err := c.PolicyStatus(ctx, "box", 0); err != nil || status.Revision.Version != 3 || status.ActiveVersion != 3 {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if status, err := c.PolicyStatus(ctx, "box", 2); err != nil || status.Revision.Status != v1.PolicyLoadStatusSuperseded ||
		status.Revision.Provenance["io.defenseclaw/reason"] != "unblock" {
		t.Fatalf("revision 2 = %+v, %v", status, err)
	}
	if cfg, err := c.SandboxConfig(ctx, "box"); err != nil || cfg.PolicyVersion != 3 || cfg.PolicySource != v1.PolicySourceSandbox {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
}

// TestGlobalPolicyDetection covers an administrator's gateway-global
// policy, which locks sandbox policy changes.
func TestGlobalPolicyDetection(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()
	createReady(t, c, "box", nil)
	if rev, err := c.GlobalPolicy(ctx); err != nil || rev != nil {
		t.Fatalf("no global policy = %+v, %v", rev, err)
	}
	f.SetGlobalPolicy(basePolicy())
	if rev, err := c.GlobalPolicy(ctx); err != nil || rev == nil || rev.Version != 1 {
		t.Fatalf("global policy = %+v, %v", rev, err)
	}
	if cfg, _ := c.SandboxConfig(ctx, "box"); cfg.PolicySource != v1.PolicySourceGlobal || cfg.GlobalPolicyVersion != 1 {
		t.Fatalf("config under global policy = %+v", cfg)
	}
	remove := []openshell.PolicyMergeOperation{{RemoveRule: &v1.RemoveNetworkRule{RuleName: "defenseclaw-egress"}}}
	if _, err := c.MergePolicy(ctx, "box", remove, openshell.PolicyUpdateOptions{}); !openshell.IsConflict(err) {
		t.Fatalf("merge under global lock = %v", err)
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
	if _, err := c.UpdateSetting(ctx, openshell.SettingUpdate{Sandbox: "box", Key: "ocsf_json_enabled", Value: &openshell.SettingValue{Type: openshell.SettingBool, BoolVal: true}}); err != nil ||
		!f.SandboxSettings(ws, "box")["ocsf_json_enabled"].BoolVal {
		t.Fatalf("sandbox setting: %v", err)
	}
	if _, err := c.UpdateSetting(ctx, openshell.SettingUpdate{Global: true, Key: "telemetry", Value: val}); err != nil {
		t.Fatal(err)
	}
	if gw, err := c.GatewaySettings(ctx); err != nil || gw.SettingsRevision != 1 {
		t.Fatalf("gateway settings = %+v, %v", gw, err)
	}
	if res, err := c.UpdateSetting(ctx, openshell.SettingUpdate{Global: true, Key: "telemetry", Delete: true}); err != nil || !res.Deleted {
		t.Fatalf("global delete = %+v, %v", res, err)
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
	var left time.Duration
	if d, ok := ctx.Deadline(); ok {
		left = time.Until(d)
	}
	h.deadline <- left
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
	_ = rec.Close()
	if _, err := c.ListSandboxes(context.Background(), nil); !openshell.IsUnavailable(err) {
		t.Fatalf("list after close = %v", err)
	}
}
