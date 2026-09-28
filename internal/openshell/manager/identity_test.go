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
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// replaceOutside deletes a sandbox outside DefenseClaw and creates another
// under its name, with labels, in phase. The fake gateway gives sandboxes
// no IDs: the box records one and the new sandbox gets another.
func replaceOutside(t *testing.T, e *harnessEnv, name string, labels map[string]string, phase openshell.SandboxPhase) *openshell.Sandbox {
	t.Helper()
	ctx := context.Background()
	e.m.mu.Lock()
	e.m.boxes[name].rec.ID = "id-" + name
	e.m.mu.Unlock()
	if _, err := e.client.DeleteSandbox(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := e.fake.SDK().Sandboxes().Create(ctx, openshell.DefaultWorkspace, name, &types.SandboxSpec{}, labels); err != nil {
		t.Fatal(err)
	}
	if err := e.fake.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
		t.Fatal(err)
	}
	sb, err := e.client.GetSandbox(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	sb.ID = "id-other-" + name
	e.fake.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
	return sb
}

// TestOperationsLeaveASandboxThatTookTheName pins that a sandbox deleted
// outside DefenseClaw and followed by another of the same name (another
// daemon's here) is never stopped, started or deleted in its place: Get
// reports it missing, Stop refuses, and Delete releases DefenseClaw's own
// state only.
func TestOperationsLeaveASandboxThatTookTheName(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.create(sandboxapi.CreateRequest{Name: "namebox"})
	other := replaceOutside(t, e, "namebox", map[string]string{LabelManaged: "true", LabelOwner: "fedcba9876543210"}, openshell.PhaseReady)

	got, err := e.m.Get(ctx, "namebox")
	if err != nil || got.Phase != "missing" {
		t.Fatalf("get = %+v, %v; want it missing", got, err)
	}
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	if _, err := e.m.Stop(ctx, "namebox"); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("stop = %v, want a conflict", err)
	}
	if n := e.fake.Calls(openshelltest.MethodStopSandbox); n != stops {
		t.Fatal("Stop stopped the other sandbox")
	}
	resp, err := e.m.Delete(ctx, "namebox", sandboxapi.DeleteRequest{})
	if err != nil || !resp.Deleted {
		t.Fatalf("delete = %+v, %v", resp, err)
	}
	now, err := e.client.GetSandbox(ctx, "namebox")
	if err != nil || now.ID != other.ID {
		t.Fatalf("Delete deleted the other sandbox: %+v, %v", now, err)
	}
	if names := e.providers(); len(names) != 0 {
		t.Fatalf("its own providers are left: %v", names)
	}
}

// TestStartLeavesASandboxThatTookTheName pins that Start refuses a stopped
// sandbox of the name that is not the one DefenseClaw created, which keeps
// the session's token out of it.
func TestStartLeavesASandboxThatTookTheName(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.create(sandboxapi.CreateRequest{Name: "startbox"})
	if _, err := e.m.Stop(ctx, "startbox"); err != nil {
		t.Fatal(err)
	}
	replaceOutside(t, e, "startbox", e.m.managedSelector(), openshell.PhaseStopped)
	starts := e.fake.Calls(openshelltest.MethodStartSandbox)
	if _, err := e.m.Start(ctx, "startbox", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("start = %v, want a conflict", err)
	}
	if n := e.fake.Calls(openshelltest.MethodStartSandbox); n != starts {
		t.Fatal("Start started a sandbox with another ID")
	}
}

// TestFailedStartRestoresThePhase pins that a start OpenShell refuses puts
// the sandbox back into the phase OpenShell reports instead of leaving it
// starting.
func TestFailedStartRestoresThePhase(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.create(sandboxapi.CreateRequest{Name: "nostart"})
	if _, err := e.m.Stop(ctx, "nostart"); err != nil {
		t.Fatal(err)
	}
	e.fake.FailNext(openshelltest.MethodStartSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	if _, err := e.m.Start(ctx, "nostart", sandboxapi.StartRequest{}); err == nil {
		t.Fatal("start succeeded")
	}
	e.m.mu.Lock()
	b := e.m.boxes["nostart"]
	phase, recorded := b.phase, b.rec.Phase
	e.m.mu.Unlock()
	if phase != audit.SandboxPhaseStopped || recorded != string(audit.SandboxPhaseStopped) {
		t.Fatalf("phase after the failed start = %s (recorded %s), want stopped", phase, recorded)
	}
}
