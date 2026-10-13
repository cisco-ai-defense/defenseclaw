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

package packs

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0537: under a profile's required pack a managed run's looser --pack
// refuses the run, naming the profile and the setting; a stricter one runs.
func TestManagedPackFlagUnderRequiredPack(t *testing.T) {
	me := ownSubject(t, t.TempDir())
	cfg := managedTestConfig(func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "balanced" })
	floor := config.OpenShellAdminConfig{RequiredPack: "balanced"}
	_, violations := mustResolve(t, cfg, Flags{Subject: me, Floor: &floor, FloorProfile: "contractors", Pack: "open"})
	v := FirstFatal(violations)
	if v == nil || v.Key != "pack" || v.Constraint != requiredPackConstraint ||
		!strings.Contains(v.Detail, "your profile contractors requires the balanced sandbox pack or a stricter one; the open pack is looser in network.mode") {
		t.Fatalf("--pack open: %+v", violations)
	}
	eff, violations := mustResolve(t, cfg, Flags{Subject: me, Floor: &floor, FloorProfile: "contractors", Pack: "strict"})
	wantViolations(t, violations)
	if eff.Pack.Name != "strict" || eff.NetworkMode != NetworkDeny {
		t.Fatalf("--pack strict: pack %s network %s", eff.Pack.Name, eff.NetworkMode)
	}
	// Outside managed computers the run keeps the required pack, as before.
	_, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "balanced" }), Flags{Pack: "open"})
	if FirstFatal(violations) != nil || len(violations) != 1 {
		t.Fatalf("OSS --pack open: %+v", violations)
	}
}

// GAP-0558, GAP-0580: a managed run's --host-port that the profile's floor
// does not open refuses the run, naming the profile; outside managed
// computers it stays a clamp the run goes ahead with.
func TestManagedHostPortFlagRefusesTheRun(t *testing.T) {
	me := ownSubject(t, t.TempDir())
	off := false
	floor := config.OpenShellAdminConfig{AllowHostPorts: &off}
	_, violations := mustResolve(t, managedTestConfig(nil), Flags{Subject: me, Floor: &floor, FloorProfile: "contractors", HostPorts: []int{8080}})
	v := FirstFatal(violations)
	if v == nil || v.Key != "mcp.host_ports" || v.Constraint != "openshell.admin.allow_host_ports" || v.Attempted != "8080" ||
		!strings.Contains(v.Detail, "your profile contractors doesn't let sandboxes reach ports on this computer") {
		t.Fatalf("managed --host-port: %+v", violations)
	}
	_, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = &off }), Flags{HostPorts: []int{8080}})
	if FirstFatal(violations) != nil || len(violations) != 1 {
		t.Fatalf("OSS --host-port: %+v", violations)
	}
}

// GAP-0537 (SPEC D2): a managed repository policy's live mount is clamped
// to copy with the managed copy-only text, not refused; elsewhere it still
// refuses the run.
func TestManagedRepoMountIsClampedToCopy(t *testing.T) {
	repo, err := ParseRepoPolicy([]byte("version: 1\nworkspace: {mode: mount}\n"), RepoPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	me := ownSubject(t, t.TempDir())
	floor := config.OpenShellAdminConfig{}
	eff, violations := mustResolve(t, managedTestConfig(nil), Flags{Subject: me, Floor: &floor, RepoPolicy: repo})
	if FirstFatal(violations) != nil || len(violations) != 1 || violations[0].Constraint != ConstraintManagedCopyOnly ||
		violations[0].Message != ReasonManagedCopyOnly || violations[0].Enforced != config.OpenShellWorkdirCopy {
		t.Fatalf("managed repo mount: %+v", violations)
	}
	wantClamped(t, eff, "workdir.mode", config.OpenShellWorkdirCopy, config.OpenShellWorkdirMount, ConstraintManagedCopyOnly)
	if eff.Workspace.Mode != config.OpenShellWorkdirCopy {
		t.Fatalf("workspace %s", eff.Workspace.Mode)
	}
	_, violations = mustResolve(t, testConfig(nil), Flags{RepoPolicy: repo})
	if v := FirstFatal(violations); v == nil || v.Key != "workspace.mode" {
		t.Fatalf("OSS repo mount: %+v", violations)
	}
}
