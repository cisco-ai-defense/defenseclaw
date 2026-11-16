// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func gap0608Host(t *testing.T, installed string) *osHost {
	t.Helper()
	h := newOSHost(t, "linux")
	h.writeExecutables(t, "/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/bin/docker")
	h.runner.replies = map[string]fakeReply{
		"rpm -q --qf %{VERSION} openshell":         {result: CommandResult{Stdout: []byte(installed)}},
		"rpm -q --qf %{VERSION} openshell-gateway": {result: CommandResult{Stdout: []byte(installed)}},
	}
	return h
}

func TestGAP0608PrerequisitePinUsesFloor(t *testing.T) {
	for _, tc := range []struct {
		pin, installed, effective string
		raised                    bool
	}{
		{"0.1.5", "0.1.6", "0.1.6", true},
		{"0.01.5", "0.1.6", "0.1.6", true},
		{">=0.1.1 <0.2.0", "0.1.6", ">=0.1.6 <0.2.0", true},
		{"0.1.6", "0.1.6", "0.1.6", false},
		{"0.1.7", "0.1.7", "0.1.7", false},
	} {
		t.Run(tc.pin, func(t *testing.T) {
			h := gap0608Host(t, tc.installed)
			r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": tc.pin}))
			requireOK(t, r)
			applied := h.env.loadOpenShellState().Applied
			if applied == nil || applied.Version != tc.effective {
				t.Fatalf("applied = %+v, want version %q", applied, tc.effective)
			}
			if tc.raised && applied.RaisedFrom != tc.pin || !tc.raised && applied.RaisedFrom != "" {
				t.Errorf("raised_from = %q", applied.RaisedFrom)
			}
			var record openshell.PrerequisitesRecord
			if err := json.Unmarshal([]byte(h.read(h.env.prerequisitesPath())), &record); err != nil || !record.Ready {
				t.Errorf("prerequisites = %+v, %v", record, err)
			}
			if state, _ := rowState(r, "sandbox openshell"); !strings.Contains(state, "version="+tc.effective) {
				t.Errorf("openshell state = %q", state)
			}
			warning := messagesOf(r.Warnings, "openshell_pin_raised")
			if tc.raised {
				if !strings.Contains(warning, "pins "+tc.pin) || !strings.Contains(warning, "OpenShell "+openshell.SupportedMin+" floor") {
					t.Errorf("floor warning = %q", warning)
				}
			} else if warning != "" {
				t.Errorf("supported pin warning = %q", warning)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				got := h.run(Options{Action: action})
				if state, _ := rowState(got, "sandbox openshell"); !strings.Contains(state, "version="+tc.effective) {
					t.Errorf("%s openshell state = %q", action, state)
				}
			}
		})
	}
}

func TestGAP0608PrerequisiteFloorSwitchWaitsForSandboxes(t *testing.T) {
	h := gap0608Host(t, openshell.SupportedMin)
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": "0.1.6"})))
	state := h.env.loadOpenShellState()
	state.Applied.Version = "0.1.5"
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1, Live: 1}
	r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": "0.1.5"}))
	requireOK(t, r)
	entry, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
	if !waiting || entry.Kind != "switch" || entry.Sandboxes != 1 || !strings.Contains(entry.Reason, `version "0.1.5" -> "0.1.6"`) || len(h.ops.stopped()) != 0 {
		t.Fatalf("pending = %+v, waiting %v, stops %v", entry, waiting, h.ops.stopped())
	}
	if warning := messagesOf(r.Warnings, codeSandboxPending); !strings.Contains(warning, "holds the change until OpenShell reports it stopped") {
		t.Errorf("pending warning = %q", warning)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	r = h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": "0.1.5"}))
	requireOK(t, r)
	if _, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]; waiting {
		t.Error("the idle account still has a pending floor switch")
	}
}

func TestGAP0608PrerequisiteRangeFloorSwitchWaitsForSandboxes(t *testing.T) {
	for _, tc := range []struct {
		name, applied, effective string
		wantSwitch               bool
	}{
		{"legacy bounded range", ">=0.1.1 <0.2.0", ">=0.1.6 <0.2.0", true},
		{"legacy open range", ">=0.1.5", ">=0.1.6", true},
		{"supported range", ">=0.1.6 <0.2.0", ">=0.1.6 <0.2.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := gap0608Host(t, openshell.SupportedMin)
			initial := sandboxConfig(t, "linux", true, map[string]any{
				"install": "prerequisite", "driver": "docker", "version": tc.effective,
			})
			requireOK(t, h.ensure(initial))
			state := h.env.loadOpenShellState()
			state.Applied.Version = tc.applied
			if err := h.env.saveOpenShellState(state); err != nil {
				t.Fatal(err)
			}
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1, Live: 1}
			configured := sandboxConfig(t, "linux", true, map[string]any{
				"install": "prerequisite", "driver": "docker", "version": tc.applied,
			})
			r := h.ensure(configured)
			requireOK(t, r)
			state = h.env.loadOpenShellState()
			if state.Applied == nil || state.Applied.Version != tc.effective {
				t.Fatalf("applied = %+v, want version %q", state.Applied, tc.effective)
			}
			entry, waiting := state.Pending[fmt.Sprint(h.alice.UID)]
			if waiting != tc.wantSwitch || len(h.ops.stopped()) != 0 {
				t.Fatalf("pending = %+v, waiting %v, stops %v", entry, waiting, h.ops.stopped())
			}
			if !tc.wantSwitch {
				return
			}
			if entry.Kind != "switch" || entry.Sandboxes != 1 || entry.From == nil || entry.From.Version != tc.applied ||
				!strings.Contains(entry.Reason, fmt.Sprintf("version %q -> %q", tc.applied, tc.effective)) {
				t.Fatalf("pending transition = %+v", entry)
			}
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
			requireOK(t, h.ensure(configured))
			if _, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]; waiting {
				t.Error("the idle account still has a pending range transition")
			}
		})
	}
}

func TestGAP0608PrerequisiteBreakingReleaseAdvice(t *testing.T) {
	for _, tc := range []struct {
		release, want string
		allowed       bool
	}{
		{"0.0.36", "back up what you need", false},
		{"0.0.37", "upgrade it in place", false},
		{"0.1.5", "runs no DefenseClaw sandbox", false},
		{"0.1.6", "", true},
	} {
		v, err := openshell.ParseVersion(tc.release)
		if err != nil {
			t.Fatal(err)
		}
		allowed, why := versionAllowed("", v)
		if allowed != tc.allowed || (tc.want == "" && why != "") || (tc.want != "" && !strings.Contains(why, tc.want)) ||
			strings.Contains(why, "clean up with the old CLI") != (tc.release == "0.0.36") {
			t.Errorf("%s: allowed=%v, advice=%q", tc.release, allowed, why)
		}
	}
}

func TestGAP0608ImpossiblePrerequisiteRangeKeepsAppliedState(t *testing.T) {
	h := gap0608Host(t, openshell.SupportedMin)
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": "0.1.6"})))
	before := h.read(h.env.prerequisitesPath())
	r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": ">=0.1.1 <0.1.6"}))
	if r.OK || !strings.Contains(fmt.Sprint(r.Errors), "no release at or above the OpenShell 0.1.6 floor") {
		t.Fatalf("impossible range result = %+v", r)
	}
	if h.read(h.env.prerequisitesPath()) != before || h.env.loadOpenShellState().Applied.Version != "0.1.6" {
		t.Error("refused range changed applied state")
	}
}
