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

package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

func newGatewayFake(t *testing.T) (*openshelltest.Fake, openshell.Client) {
	t.Helper()
	f := openshelltest.New()
	c := f.Client(openshell.ClientOptions{})
	t.Cleanup(func() { _ = c.Close() })
	return f, c
}

func addSandbox(f *openshelltest.Fake, name string, labels map[string]string, phase openshell.SandboxPhase, created time.Time, deleting bool) {
	sb := &openshell.Sandbox{Name: name, Labels: labels, CreatedAt: created, Status: openshell.SandboxStatus{Phase: phase}}
	if deleting {
		sb.DeletionTimestamp = &created
	}
	f.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
}

func TestGatewayClientFindsResumableSandboxes(t *testing.T) {
	e := newEnv(t)
	f, c := newGatewayFake(t)
	key, value := ProjectLabel(e.project)
	mine := map[string]string{key: value, ModeLabelKey: "copy"}
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	addSandbox(f, "older", mine, openshell.PhaseStopped, t0, false)
	addSandbox(f, "newer", mine, openshell.PhaseReady, t0.Add(time.Hour), false)
	addSandbox(f, "going", mine, openshell.PhaseReady, t0.Add(2*time.Hour), true)
	addSandbox(f, "failed", mine, openshell.PhaseError, t0.Add(3*time.Hour), false)
	addSandbox(f, "other", map[string]string{key: ProjectKey("/elsewhere")}, openshell.PhaseReady, t0, false)

	got, err := FindResumable(bg, GatewayClient{Client: c}, e.data, e.project)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, cand := range got {
		names = append(names, cand.Sandbox.Name+":"+cand.Mode)
	}
	if strings.Join(names, ",") != "newer:copy,older:copy" {
		t.Fatalf("candidates = %v", names)
	}

	boxes, err := GatewayClient{Client: c}.FindSandboxes(bg, map[string]string{key: value})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range boxes {
		if b.Name == "going" && b.Phase != string(openshell.PhaseDeleting) {
			t.Fatalf("a sandbox being deleted reports phase %q", b.Phase)
		}
	}
}

func TestGatewayClientExecFollowsTheOpenShellRules(t *testing.T) {
	f, c := newGatewayFake(t)
	addSandbox(f, "box", nil, openshell.PhaseReady, time.Now(), false)
	g := GatewayClient{Client: c}

	f.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{Stdout: []byte(strings.Join(call.Command, " ")), Stderr: []byte(call.Env["A"] + call.WorkDir), ExitCode: 3}
	})
	res, err := g.Exec(bg, "box", ExecRequest{Argv: []string{"git", "status"}, Workdir: "/w", Env: map[string]string{"A": "1"}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "git status" || string(res.Stderr) != "1/w" || res.ExitCode != 3 {
		t.Fatalf("result = %+v", res)
	}
	if call := f.ExecCalls()[0]; call.Timeout != time.Minute {
		t.Fatalf("the sandbox limit is %s, want the request's timeout", call.Timeout)
	}

	// An attempt the gateway never answers is rerun only for an idempotent
	// request; the sandbox has stopped the first run by then.
	for _, idempotent := range []bool{false, true} {
		calls := 0
		f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
			calls++
			if calls == 1 {
				return openshelltest.ExecResponse{Hang: true}
			}
			return openshelltest.ExecResponse{Stdout: []byte("ok\n")}
		})
		res, err := g.Exec(bg, "box", ExecRequest{Argv: []string{"true"}, Timeout: 20 * time.Millisecond, Idempotent: idempotent})
		switch {
		case idempotent && (err != nil || string(res.Stdout) != "ok\n" || calls != 2):
			t.Fatalf("idempotent: res=%+v err=%v calls=%d", res, err, calls)
		case !idempotent && (!errors.Is(err, openshell.ErrExecTimeout) || calls != 1):
			t.Fatalf("not idempotent: res=%+v err=%v calls=%d", res, err, calls)
		}
	}
}

func TestUnsupportedPlatformIsTheOpenShellSentinel(t *testing.T) {
	if !errors.Is(ErrUnsupportedPlatform, openshell.ErrUnsupportedPlatform) ||
		!errors.Is(openshell.CheckPlatform("windows"), ErrUnsupportedPlatform) {
		t.Fatal("the two packages report the platform with different sentinels")
	}
}
