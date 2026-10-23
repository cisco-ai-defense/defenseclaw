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

package enterpriseunix

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestSandboxSwitchWaitsForComputeThatMayStillRun: the automatic move of
// 1.0.3's setup pin "0.1.3" to the release sandboxes need is a switch,
// which stops the account's OpenShell gateway. It waits, as for a running
// sandbox, while the account's daemon counts one that may still hold
// compute (sandboxapi.Status.Live: a MicroVM in OpenShell's error state,
// which nothing can flush first, or a sandbox still starting), and goes
// ahead once none does. So do the other changes that stop the gateway or
// daemon (a driver switch, sandboxes turned off).
func TestSandboxSwitchWaitsForComputeThatMayStillRun(t *testing.T) {
	old := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.3"}
	t.Run("the pin migration", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, old)))
		st := h.env.loadOpenShellState()
		st.Applied.Version = "0.1.3"
		if err := h.env.saveOpenShellState(st); err != nil {
			t.Fatal(err)
		}
		h.installTarballFiles(t, h.alice, "0.1.3")
		// No sandbox is ready, but a MicroVM is in OpenShell's error state.
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 0, Live: 1}
		r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), ConfigFile: writeTempConfig(t, sandboxConfig(t, "linux", true, old))})
		requireOK(t, r)
		if containsLine(r.Changes, "switched the sandbox setup of alice") || len(h.ops.stopped()) != 0 {
			t.Fatalf("switched under a sandbox that may still run: changes %v, stops %v", r.Changes, h.ops.stopped())
		}
		entry, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
		if !waiting || entry.Kind != "switch" || entry.Sandboxes != 1 || !strings.Contains(entry.Reason, `version "0.1.3" -> "`+openshell.InstallerVersion+`"`) {
			t.Fatalf("pending = %+v, %v", entry, waiting)
		}
		if w := messagesOf(r.Warnings, codeSandboxPending); !strings.Contains(w, "1 sandbox runs (or is starting, stopping, or a MicroVM that OpenShell does not report stopped)") ||
			!strings.Contains(w, "holds the change until OpenShell reports it stopped") || strings.Contains(w, "lets the change") ||
			strings.Contains(w, "disk back") {
			t.Errorf("warnings = %v", r.Warnings)
		}
		// Stopped or deleted: the next run switches.
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
		r = h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), ConfigFile: writeTempConfig(t, sandboxConfig(t, "linux", true, old))})
		requireOK(t, r)
		if !containsLine(r.Changes, `switched the sandbox setup of alice (version "0.1.3" -> "`+openshell.InstallerVersion+`")`) {
			t.Fatalf("changes = %v", r.Changes)
		}
	})
	t.Run("sandboxes turned off", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"})))
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Live: 2}
		requireOK(t, h.ensure(sandboxConfig(t, "linux", false, map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"})))
		if entry := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]; entry.Kind != "stop" || entry.Sandboxes != 2 || len(h.ops.stopped()) != 0 {
			t.Fatalf("pending = %+v, stops %v", entry, h.ops.stopped())
		}
	})
}

// TestCommandOpsCountsComputeThatMayStillRun: the account's daemon reports
// Live; one from before DefenseClaw 1.0.4 does not, and then every sandbox
// it counts may still run.
func TestCommandOpsCountsComputeThatMayStillRun(t *testing.T) {
	for _, tc := range []struct {
		reply         string
		running, live int
	}{
		{`{"running":0,"sandboxes":3,"live":1}`, 0, 1},
		{`{"running":2,"sandboxes":3,"live":2}`, 2, 2},
		{`{"running":0,"sandboxes":3,"live":0}`, 0, 0},
		{`{"running":1,"sandboxes":3}`, 1, 3},
		{`{"running":0}`, 0, 0},
	} {
		ops, _, alice := opsHost(t, "linux", func(line string) (CommandResult, error) {
			switch {
			case strings.HasSuffix(line, "systemctl --user is-active defenseclaw-sandbox.service"):
				return CommandResult{Stdout: []byte("active\n")}, nil
			case strings.HasSuffix(line, "sandbox status --output json"):
				return CommandResult{Stdout: []byte(tc.reply)}, nil
			}
			return CommandResult{}, nil
		})
		st, err := ops.Status(context.Background(), alice)
		if err != nil || st.Running != tc.running || st.Live != tc.live || st.busy() != max(tc.running, tc.live) {
			t.Errorf("%s: Status = %+v, %v", tc.reply, st, err)
		}
	}
}

// TestPrerequisiteVersionRefusesPrereleases: in prerequisite mode the
// administrator's OpenShell, read from rpm (%{VERSION} 0.1.5~pre.3), dpkg
// (0.1.5~pre.3-1) or `--version` (0.1.5-pre.3), fails its row when it is a
// prerelease of the release sandboxes need, whatever the pin allows; a
// range's ceiling holds its own prereleases out.
func TestPrerequisiteVersionRefusesPrereleases(t *testing.T) {
	parse := func(s string) openshell.Version {
		t.Helper()
		v, err := openshell.ParseVersion(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		spec, have string
		ok         bool
	}{
		{"", "0.1.5~pre.3", false},
		{"", "0.1.5~pre.3-1", false},
		{"", "openshell 0.1.5-pre.3", false},
		{">=0.1.1 <0.2.0", "0.1.5-pre.7", false},
		{">=0.1.5 <0.2.0", "0.1.5-pre.7", false},
		{"0.1.5", "0.1.5-pre.7", false},
		{"", "0.1.5-1", true},
		{"0.1.5", "0.1.5-1", true},
		{">=0.1.5 <0.1.9", "0.1.9-pre.1", false},
		{">=0.1.5 <0.2.0", "0.1.6-pre.1", true},
	} {
		if ok, why := versionAllowed(tc.spec, parse(tc.have)); ok != tc.ok {
			t.Errorf("versionAllowed(%q, %s) = %v (%s)", tc.spec, tc.have, ok, why)
		}
	}
}
