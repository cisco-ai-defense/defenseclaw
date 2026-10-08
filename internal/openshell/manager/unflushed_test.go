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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// TestAMicroVMThatWentDownUnflushedIsNamed (GAP-0289): `brew services
// restart` of the gateway mid-write took a MicroVM down without a flush,
// and the file it wrote came back with a zero-filled tail while the feed
// said only "is provisioning", "is ready". A MicroVM that leaves the ready
// phase without DefenseClaw stopping it gets a warning; one DefenseClaw
// stops, and a Docker sandbox, do not.
func TestAMicroVMThatWentDownUnflushedIsNamed(t *testing.T) {
	warned := func(e *harnessEnv, name string) int {
		return len(e.events(name, sandboxapi.ActivityFinding, sandboxapi.ReasonUnflushedStop))
	}
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "vmbox", Copy: true})
	e.m.statusEvent(t.Context(), e.boxOf("vmbox"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("vmbox"), &stream.Status{Phase: openshell.PhaseReady})
	if n := warned(e, "vmbox"); n != 1 {
		t.Fatalf("unflushed warnings = %d, want 1", n)
	}
	if got := e.events("vmbox", sandboxapi.ActivityFinding, sandboxapi.ReasonUnflushedStop)[0]; got.Message != unflushedStopMessage("vmbox") || got.Severity != "MEDIUM" {
		t.Fatalf("warning = %+v", got)
	}
	e.stopBox("vmbox")
	if n := warned(e, "vmbox"); n != 1 {
		t.Fatalf("a stop of DefenseClaw's warned too: %d", n)
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dkbox"})
	d.m.statusEvent(t.Context(), d.boxOf("dkbox"), &stream.Status{Phase: openshell.PhaseProvisioning})
	if n := warned(d, "dkbox"); n != 0 {
		t.Fatalf("a Docker sandbox, whose stop flushes, warned: %d", n)
	}
}
