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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A raw OpenShell start changes the live VM without updating the manager's
// cached phase. A stop must sync the live guest; the inverse stale-cache case
// must not try to exec into a VM OpenShell already stopped.
func TestStopUsesFreshMicroVMPhaseAfterRawTransition(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cached     audit.SandboxPhase
		live       openshell.SandboxPhase
		wantSynced bool
	}{
		{"raw start after a recorded stop", audit.SandboxPhaseStopped, openshell.PhaseReady, true},
		{"raw stop after a recorded start", audit.SandboxPhaseReady, openshell.PhaseStopped, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
			if tc.cached == audit.SandboxPhaseStopped {
				e.stopBox("box")
			}
			must(t, e.fake.SetPhase(openshell.DefaultWorkspace, "box", tc.live))
			b := e.boxOf("box")
			e.m.mu.Lock()
			cached := b.phase
			e.m.mu.Unlock()
			if cached != tc.cached {
				t.Fatalf("test requires cached %s, got %s", tc.cached, cached)
			}
			e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
				return openshelltest.ExecResponse{Stdout: []byte("none\nsynced\n")}
			}))
			before := len(e.fake.ExecCalls())
			if _, err := e.m.Stop(t.Context(), "box"); err != nil {
				t.Fatal(err)
			}
			calls := e.fake.ExecCalls()[before:]
			synced := false
			for _, call := range calls {
				if len(call.Command) >= 3 && strings.HasPrefix(call.Command[2], flushTrap) {
					synced = true
				}
			}
			if synced != tc.wantSynced {
				t.Fatalf("live phase %s, cached %s: sync attempted %v, want %v; exec calls %+v", tc.live, tc.cached, synced, tc.wantSynced, calls)
			}
		})
	}
}
