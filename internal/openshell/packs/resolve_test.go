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
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	sandboxpolicies "github.com/defenseclaw/defenseclaw/policies/sandbox"
)

func boolPtr(v bool) *bool { return &v }

func testConfig(edit func(*config.OpenShellConfig)) *config.Config {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	if edit != nil {
		edit(&cfg.OpenShell)
	}
	return cfg
}

func mustResolve(t *testing.T, cfg *config.Config, flags Flags) (*Effective, []Violation) {
	t.Helper()
	eff, violations, err := Resolve(cfg, flags)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return eff, violations
}

func wantSetting(t *testing.T, eff *Effective, key, value string, source Source, origin string) {
	t.Helper()
	got, ok := eff.Setting(key)
	if !ok {
		t.Fatalf("no setting %q", key)
	}
	if got.Value != value || got.Source != source || (origin != "" && got.Origin != origin) {
		t.Fatalf("setting %s = %+v, want value %q source %q origin %q", key, got, value, source, origin)
	}
}

func onlyViolation(t *testing.T, violations []Violation) Violation {
	t.Helper()
	if len(violations) != 1 {
		t.Fatalf("violations = %+v, want exactly one", violations)
	}
	return violations[0]
}

// teamPackDir returns a pack_dir holding the minimal custom pack "team".
func teamPackDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writePack(t, root, "team", customPack("team"))
	return root
}

func TestResolveDefaults(t *testing.T) {
	eff, violations := mustResolve(t, testConfig(nil), Flags{})
	wantViolations(t, violations)
	wantPosture(t, eff, "pack=open profile=open network="+NetworkOpen+" approvals="+ApprovalsAuto+" yolo=true mode=mount import=true"+
		" host_port_access=true host_ports= learn=false harness= any_harness=true fail_mode="+FailModeClosed+" on_tamper="+OnTamperAlert+
		" project_servers="+MCPProjectServersBlock+" feeds="+FeedBuiltin+" ports=80,443 block= admin_block= cpu= memory=")
	if eff.AllowedHarnesses == nil || len(eff.AllowedHarnesses) != 0 || eff.Egress.LargeUploadMB != 25 {
		t.Fatalf("allowed harnesses %#v large upload %d", eff.AllowedHarnesses, eff.Egress.LargeUploadMB)
	}
	if eff.Workspace.MaxUploadMB != 500 || eff.Workspace.GitDepth != 200 || eff.Workspace.OnExit != "ask" ||
		!containsString(eff.Workspace.Unmask, ".env.example") || !containsString(eff.Workspace.Masks, ".env.*") {
		t.Fatalf("workspace = %+v", eff.Workspace)
	}
	if eff.Admin.Configured || eff.Admin.Authority != AuthorityAdvisory {
		t.Fatalf("admin status = %+v", eff.Admin)
	}
	wantSetting(t, eff, "pack", "open", SourceDefault, "default pack")
	wantSetting(t, eff, "profile", "open", SourcePack, "pack open")
	wantSetting(t, eff, "yolo", "true", SourcePack, "pack open")
	wantSetting(t, eff, "workdir.unmask", ".env.example, .env.sample, .env.template, .env.dist", SourcePack, "pack open")
	wantSetting(t, eff, "workdir.git_depth", "200", SourceDefault, "")
	wantSetting(t, eff, "mcp.host_ports", "(none)", SourceDefault, "")
	wantSetting(t, eff, "resources.cpu", "(unlimited)", SourceDefault, "")
	wantSetting(t, eff, "learn", "false", SourceDefault, "")
	wantSetting(t, eff, "hooks.fail_mode", "closed", SourcePack, "pack open")
	wantSetting(t, eff, "hooks.on_tamper", "alert", SourcePack, "pack open")
	wantSetting(t, eff, "mcp.project_servers", "block", SourcePack, "pack open")

	// The loader defaults (git_depth 200, on_exit ask) read as defaults.
	loaded := testConfig(func(o *config.OpenShellConfig) {
		o.Workdir.GitDepth = config.DefaultOpenShellGitDepth
		o.Workdir.OnExit = config.DefaultOpenShellOnExit
	})
	eff, _ = mustResolve(t, loaded, Flags{})
	wantSetting(t, eff, "workdir.on_exit", "ask", SourceDefault, "")
}

func TestResolveLayering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		user   func(*config.OpenShellConfig)
		flags  Flags
		key    string
		value  string
		source Source
		origin string
	}{
		{"pack by user", func(o *config.OpenShellConfig) { o.Pack = "balanced" }, Flags{}, "pack", "balanced", SourceUser, "openshell.pack"},
		{"pack by flag", func(o *config.OpenShellConfig) { o.Pack = "balanced" }, Flags{Pack: "strict"}, "pack", "strict", SourceFlag, "--pack"},
		{"profile from pack", func(o *config.OpenShellConfig) { o.Pack = "balanced" }, Flags{}, "profile", "balanced", SourcePack, "pack balanced"},
		{"profile by user", func(o *config.OpenShellConfig) { o.Profile = "strict" }, Flags{}, "profile", "strict", SourceUser, "openshell.profile"},
		{"profile by flag", func(o *config.OpenShellConfig) { o.Profile = "strict" }, Flags{Profile: "balanced"}, "profile", "balanced", SourceFlag, "--profile"},
		{"network follows profile", nil, Flags{Profile: "strict"}, "network.mode", NetworkDeny, SourceFlag, "profile strict"},
		{"yolo by user", func(o *config.OpenShellConfig) { o.Yolo = boolPtr(false) }, Flags{}, "yolo", "false", SourceUser, "openshell.yolo"},
		{"yolo by flag", func(o *config.OpenShellConfig) { o.Yolo = boolPtr(false) }, Flags{Yolo: true}, "yolo", "true", SourceFlag, "--yolo"},
		{"safe wins", nil, Flags{Yolo: true, Safe: true}, "yolo", "false", SourceFlag, "--safe"},
		{"yolo from strict pack", func(o *config.OpenShellConfig) { o.Pack = "strict" }, Flags{}, "yolo", "false", SourcePack, "pack strict"},
		{"workdir by user", func(o *config.OpenShellConfig) { o.Workdir.Mode = "copy" }, Flags{}, "workdir.mode", "copy", SourceUser, "openshell.workdir.mode"},
		{"workdir by flag", nil, Flags{Copy: true}, "workdir.mode", "copy", SourceFlag, "--copy"},
		{"masks merge", func(o *config.OpenShellConfig) { o.Workdir.Masks = []string{"secrets/**"} }, Flags{}, "workdir.masks", "", SourceUser, "pack open + openshell.workdir.masks"},
		{"unmask by user", func(o *config.OpenShellConfig) { o.Workdir.Unmask = []string{"certs/dev.pem"} }, Flags{}, "workdir.unmask", "", SourceUser, "pack open + openshell.workdir.unmask"},
		{"unmask by user over a pack without unmask", func(o *config.OpenShellConfig) {
			o.Pack, o.PackDir = "team", teamPackDir(t)
			o.Workdir.Unmask = []string{"certs/dev.pem"}
		}, Flags{}, "workdir.unmask", "certs/dev.pem", SourceUser, "openshell.workdir.unmask"},
		{"unmask merge flag", func(o *config.OpenShellConfig) { o.Workdir.Unmask = []string{".env.example"} }, Flags{Unmask: []string{"certs/dev.pem", ".env.example"}}, "workdir.unmask", ".env.example, .env.sample, .env.template, .env.dist, certs/dev.pem", SourceFlag, "--unmask"},
		{"upload cap by user", func(o *config.OpenShellConfig) { o.Workdir.MaxUploadMB = 50 }, Flags{}, "workdir.max_upload_mb", "50", SourceUser, ""},
		{"git depth by user", func(o *config.OpenShellConfig) { o.Workdir.GitDepth = 20 }, Flags{}, "workdir.git_depth", "20", SourceUser, ""},
		{"on exit by user", func(o *config.OpenShellConfig) { o.Workdir.OnExit = "keep" }, Flags{}, "workdir.on_exit", "keep", SourceUser, ""},
		{"feed off", func(o *config.OpenShellConfig) { o.Egress.Feed = "none" }, Flags{}, "egress.feeds", "(none)", SourceUser, "openshell.egress.feed"},
		{"feed builtin", func(o *config.OpenShellConfig) { o.Egress.Feed = "builtin" }, Flags{}, "egress.feeds", "builtin", SourceUser, "openshell.egress.feed"},
		{"block merges", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"Paste.Example."} }, Flags{}, "egress.block", "paste.example", SourceUser, "pack open + openshell.egress.block"},
		{"allow merges", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"*.corp.example"} }, Flags{}, "egress.allow", "*.corp.example", SourceUser, ""},
		{"ports replace", func(o *config.OpenShellConfig) { o.Egress.Ports = []int{443, 8443, 443} }, Flags{}, "egress.ports", "443, 8443", SourceUser, "openshell.egress.ports"},
		{"large upload by user", func(o *config.OpenShellConfig) { o.Egress.LargeUploadMB = 5 }, Flags{}, "egress.large_upload_mb", "5", SourceUser, ""},
		{"mcp import by user", func(o *config.OpenShellConfig) { o.MCP.Import = boolPtr(false) }, Flags{}, "mcp.import", "false", SourceUser, "openshell.mcp.import"},
		{"no-mcp flag", func(o *config.OpenShellConfig) { o.MCP.Import = boolPtr(true) }, Flags{NoMCP: true}, "mcp.import", "false", SourceFlag, "--no-mcp"},
		{"host ports by user", func(o *config.OpenShellConfig) { o.MCP.HostPorts = []int{5432} }, Flags{}, "mcp.host_ports", "5432", SourceUser, ""},
		{"host ports by flag", func(o *config.OpenShellConfig) { o.MCP.HostPorts = []int{5432} }, Flags{HostPorts: []int{6379, 5432}}, "mcp.host_ports", "5432, 6379", SourceFlag, "--host-port"},
		{"cpu by user", func(o *config.OpenShellConfig) { o.Resources.CPU = "2" }, Flags{}, "resources.cpu", "2", SourceUser, "openshell.resources.cpu"},
		{"cpu by flag", func(o *config.OpenShellConfig) { o.Resources.CPU = "2" }, Flags{CPU: "500m"}, "resources.cpu", "500m", SourceFlag, "--cpu"},
		{"memory by flag", nil, Flags{Memory: "4Gi"}, "resources.memory", "4Gi", SourceFlag, "--memory"},
		{"harness", nil, Flags{Harness: "claude-code"}, "harness", "claudecode", SourceFlag, ""},
		{"learn", nil, Flags{Learn: true}, "learn", "true", SourceFlag, "--learn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, testConfig(tc.user), tc.flags)
			if len(violations) != 0 {
				t.Fatalf("violations = %+v", violations)
			}
			got, _ := eff.Setting(tc.key)
			if tc.value == "" {
				tc.value = got.Value
			}
			wantSetting(t, eff, tc.key, tc.value, tc.source, tc.origin)
		})
	}

	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Workdir.Masks = []string{"secrets/**", ".env"}
		o.Egress.Block = []string{"paste.example"}
		o.Egress.Allow = []string{"*.corp.example"}
	}), Flags{Harness: "Codex", CPU: "1", Memory: "2Gi"})
	if last := eff.Workspace.Masks[len(eff.Workspace.Masks)-1]; last != "secrets/**" || strings.Count(strings.Join(eff.Workspace.Masks, ","), ".env,") != 1 {
		t.Fatalf("masks = %v", eff.Workspace.Masks)
	}
	if !reflect.DeepEqual(eff.Egress.Block, []string{"paste.example"}) || !reflect.DeepEqual(eff.Egress.Allow, []string{"*.corp.example"}) {
		t.Fatalf("egress lists = %+v", eff.Egress)
	}
	wantPosture(t, eff, "harness=codex cpu=1 memory=2Gi")
}

// The large-upload block is off unless the pack, the user's
// openshell.egress.block_large_uploads or the administrator turns it on.
// The user's key cannot turn a pack's block off, and under the
// administrator's block the report it acts on stays on: a pack that turns it
// off gets the default threshold, and the user who picked that pack is told.
func TestResolveLargeUploadBlock(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "blocking", strings.Replace(customPack("blocking"), "network: {mode: open}",
		"network: {mode: open}\negress: {large_upload_mb: 5, block_large_uploads: true}", 1))
	writePack(t, root, "silent", strings.Replace(customPack("silent"), "network: {mode: open}",
		"network: {mode: open}\negress: {large_upload_mb: 0}", 1))
	writePack(t, root, "blind", strings.Replace(customPack("blind"), "network: {mode: open}",
		"network: {mode: open}\negress: {large_upload_mb: 0, block_large_uploads: true}", 1))
	writePack(t, root, "huge", strings.Replace(customPack("huge"), "network: {mode: open}",
		"network: {mode: open}\negress: {large_upload_mb: 1048576}", 1))
	writePack(t, root, "roomy", strings.Replace(customPack("roomy"), "network: {mode: open}",
		"network: {mode: open}\negress: {large_upload_mb: 100}", 1))
	for _, tc := range []struct {
		name          string
		edit          func(*config.OpenShellConfig)
		block         bool
		source        Source
		origin        string
		largeUploadMB int
		violation     *Violation
	}{
		{"default", nil, false, SourcePack, "pack open", 25, nil},
		{"user", func(o *config.OpenShellConfig) { o.Egress.BlockLargeUploads = true }, true, SourceUser,
			"openshell.egress.block_large_uploads", 25, nil},
		{"pack", func(o *config.OpenShellConfig) { o.Pack = "blocking" }, true, SourcePack, "pack blocking", 5, nil},
		{"user over a blocking pack", func(o *config.OpenShellConfig) {
			o.Pack, o.Egress.BlockLargeUploads = "blocking", true
		}, true, SourcePack, "pack blocking", 5, nil},
		{"admin", func(o *config.OpenShellConfig) { o.Admin.BlockLargeUploads = true }, true, SourceAdmin,
			"openshell.admin.block_large_uploads", 25, nil},
		{"admin over a pack without the report", func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.BlockLargeUploads = "silent", true
		}, true, SourceAdmin, "openshell.admin.block_large_uploads", 25, &Violation{
			Key: "egress.large_upload_mb", Source: SourcePack, Attempted: "0", Enforced: "25",
			Constraint: "openshell.admin.block_large_uploads", Detail: "the large-upload report stays on",
		}},
		{"pack without the report", func(o *config.OpenShellConfig) { o.Pack = "silent" }, false, SourcePack, "pack silent", 0, nil},
		// The block acts on the report: without one it cuts nothing, so it
		// is off, and whoever asked for it is told.
		{"user over a pack without the report", func(o *config.OpenShellConfig) {
			o.Pack, o.Egress.BlockLargeUploads = "silent", true
		}, false, SourceUser, "openshell.egress.block_large_uploads", 0, &Violation{
			Key: "egress.block_large_uploads", Source: SourceUser, Attempted: "true", Enforced: "false",
			Constraint: "egress.large_upload_mb", Detail: "above 0",
		}},
		{"pack blocking without the report", func(o *config.OpenShellConfig) { o.Pack = "blind" }, false, SourcePack, "pack blind", 0,
			&Violation{Key: "egress.block_large_uploads", Source: SourcePack, Attempted: "true", Enforced: "false"}},
		// Under the administrator's block a raised threshold is as good as
		// no report: it is at most the default, or the required pack's.
		{"admin over a pack's raised threshold", func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.BlockLargeUploads = "huge", true
		}, true, SourceAdmin, "openshell.admin.block_large_uploads", 25, &Violation{
			Key: "egress.large_upload_mb", Source: SourcePack, Attempted: "1048576", Enforced: "25",
			Constraint: "openshell.admin.block_large_uploads", Detail: "at most 25 MiB",
		}},
		{"admin over the user's raised threshold", func(o *config.OpenShellConfig) {
			o.Egress.LargeUploadMB, o.Admin.BlockLargeUploads = 1048576, true
		}, true, SourceAdmin, "openshell.admin.block_large_uploads", 25, &Violation{
			Key: "egress.large_upload_mb", Source: SourceUser, Attempted: "1048576", Enforced: "25",
			Constraint: "openshell.admin.block_large_uploads",
		}},
		{"admin keeps the user's lower threshold", func(o *config.OpenShellConfig) {
			o.Egress.LargeUploadMB, o.Admin.BlockLargeUploads = 10, true
		}, true, SourceAdmin, "openshell.admin.block_large_uploads", 10, nil},
		{"admin over a required pack's higher threshold", func(o *config.OpenShellConfig) {
			o.Admin.RequiredPack, o.Egress.LargeUploadMB, o.Admin.BlockLargeUploads = "roomy", 200, true
		}, true, SourceAdmin, "openshell.admin.block_large_uploads", 100, &Violation{
			Key: "egress.large_upload_mb", Source: SourceUser, Attempted: "200", Enforced: "100",
			Constraint: "openshell.admin.block_large_uploads", Detail: "at most 100 MiB",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
				o.PackDir = root
				if tc.edit != nil {
					tc.edit(o)
				}
			}), Flags{})
			if tc.violation == nil {
				wantViolations(t, violations)
			} else {
				wantViolations(t, violations, *tc.violation)
			}
			if eff.Egress.BlockLargeUploads != tc.block || eff.Egress.LargeUploadMB != tc.largeUploadMB {
				t.Fatalf("egress = %+v, want block %v at %d MiB", eff.Egress, tc.block, tc.largeUploadMB)
			}
			wantSetting(t, eff, "egress.block_large_uploads", strconv.FormatBool(tc.block), tc.source, tc.origin)
			if tc.violation != nil && tc.violation.Key == "egress.large_upload_mb" {
				wantSetting(t, eff, "egress.large_upload_mb", strconv.Itoa(tc.largeUploadMB), SourceAdmin, "openshell.admin.block_large_uploads")
			}
		})
	}
}

func TestResolveApprovalsFollowProfile(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "auto", strings.Replace(customPack("auto"), "mode: triage", "mode: auto", 1))
	for _, tc := range []struct {
		profile, approvals string
		source             Source
	}{
		{"open", ApprovalsAuto, SourcePack},
		{"balanced", ApprovalsTriage, SourceFlag},
		{"strict", ApprovalsManual, SourceFlag},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			cfg := testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "auto", root })
			eff, _ := mustResolve(t, cfg, Flags{Profile: tc.profile})
			if eff.Approvals != tc.approvals {
				t.Fatalf("approvals = %q, want %q", eff.Approvals, tc.approvals)
			}
			wantSetting(t, eff, "approvals.mode", tc.approvals, tc.source, "")
		})
	}
	// A looser profile never loosens the pack's approvals.
	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Pack = "strict" }), Flags{Profile: "open"})
	if eff.Profile != "open" || eff.Approvals != ApprovalsManual {
		t.Fatalf("profile %q approvals %q", eff.Profile, eff.Approvals)
	}
}

// wantViolations fails unless violations match want one to one: each wanted
// Key, Source, Attempted, Enforced and Constraint that is set must be equal,
// Detail must be contained, and Fatal must agree.
func wantViolations(t *testing.T, violations []Violation, want ...Violation) {
	t.Helper()
	if len(violations) != len(want) {
		t.Fatalf("violations = %+v, want %d", violations, len(want))
	}
	for i, w := range want {
		v := violations[i]
		if (w.Key != "" && v.Key != w.Key) || (w.Source != "" && v.Source != w.Source) ||
			(w.Attempted != "" && v.Attempted != w.Attempted) || (w.Enforced != "" && v.Enforced != w.Enforced) ||
			(w.Constraint != "" && v.Constraint != w.Constraint) || !strings.Contains(v.Detail, w.Detail) || v.Fatal != w.Fatal {
			t.Fatalf("violation %d = %+v, want %+v", i, v, w)
		}
	}
}

// wantPosture checks the enforced values of eff named in want
// ("yolo=false mode=copy host_ports=5432,6379"; lists join with commas).
func wantPosture(t *testing.T, eff *Effective, want string) {
	t.Helper()
	s := func(v any) string { return strings.Trim(strings.Join(strings.Fields(fmt.Sprint(v)), ","), "[]") }
	got := map[string]string{
		"pack": eff.Pack.Name, "profile": eff.Profile, "network": s(eff.NetworkMode), "approvals": s(eff.Approvals),
		"yolo": s(eff.Yolo), "mode": eff.Workspace.Mode, "import": s(eff.MCP.Import), "learn": s(eff.Learn),
		"harness": eff.Harness, "any_harness": s(eff.AnyHarness), "fail_mode": s(eff.HookFailMode), "on_tamper": s(eff.HookOnTamper),
		"project_servers": s(eff.MCP.ProjectServers), "host_port_access": s(eff.MCP.HostPortAccess), "host_ports": s(eff.MCP.HostPorts),
		"feeds": s(eff.Egress.Feeds), "ports": s(eff.Egress.Ports), "block": s(eff.Egress.Block), "admin_block": s(eff.Egress.AdminBlock),
		"unmask": s(eff.Workspace.Unmask), "cpu": eff.Resources.CPU, "memory": eff.Resources.Memory,
	}
	for _, kv := range strings.Fields(want) {
		key, value, _ := strings.Cut(kv, "=")
		if v, ok := got[key]; !ok || v != value {
			t.Fatalf("%s = %q, want %q", key, v, value)
		}
	}
}

// wantClamped checks a setting an administrator constraint replaced.
func wantClamped(t *testing.T, eff *Effective, key, value, requested, origin string) {
	t.Helper()
	got, _ := eff.Setting(key)
	if got.Value != value || got.Source != SourceAdmin || got.Requested != requested || (origin != "" && got.Origin != origin) {
		t.Fatalf("setting %s = %+v, want %q clamped from %q by %q", key, got, value, requested, origin)
	}
}

func TestResolveAdminClamps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		user    func(*config.OpenShellConfig)
		flags   Flags
		want    []Violation
		posture string
		check   func(t *testing.T, eff *Effective, violations []Violation)
	}{
		{"min profile clamps the user", func(o *config.OpenShellConfig) { o.Profile, o.Admin.MinProfile = "open", "balanced" }, Flags{},
			[]Violation{{Key: "profile", Source: SourceUser, Attempted: "open", Enforced: "balanced", Constraint: "openshell.admin.min_profile"}},
			"profile=balanced network=" + NetworkAllowlist + " approvals=" + ApprovalsTriage, func(t *testing.T, eff *Effective, violations []Violation) {
				if v := violations[0]; v.Message != "blocked by your organization's DefenseClaw policy: profile" ||
					!strings.Contains(v.Error(), "at least the balanced profile") {
					t.Fatalf("message = %q", v.Error())
				}
				wantClamped(t, eff, "profile", "balanced", "open", "openshell.admin.min_profile")
				wantSetting(t, eff, "network.mode", NetworkAllowlist, SourceAdmin, "profile balanced")
			}},
		{"min profile clamps a flag", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "strict" }, Flags{Profile: "balanced"},
			[]Violation{{Key: "profile", Source: SourceFlag, Enforced: "strict"}}, "profile=strict approvals=" + ApprovalsManual, nil},
		{"min profile silently raises the default pack", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" }, Flags{}, nil,
			"profile=balanced", func(t *testing.T, eff *Effective, _ []Violation) {
				wantClamped(t, eff, "profile", "balanced", "open", "")
			}},
		{"min profile keeps a stricter choice", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" }, Flags{Profile: "strict"},
			nil, "profile=strict", nil},
		{"allow-only forces an allowlist profile", func(o *config.OpenShellConfig) {
			o.Profile, o.Admin.EgressAllowOnly = "open", []string{"*.Corp.Example"}
		}, Flags{}, []Violation{{Key: "profile", Constraint: "openshell.admin.egress_allow_only"}}, "profile=balanced",
			func(t *testing.T, eff *Effective, _ []Violation) {
				if !reflect.DeepEqual(eff.Egress.AllowOnly, []string{"*.corp.example"}) {
					t.Fatalf("allow-only %v", eff.Egress.AllowOnly)
				}
			}},
		{"min profile beats allow-only", func(o *config.OpenShellConfig) {
			o.Admin.EgressAllowOnly, o.Admin.MinProfile = []string{"corp.example"}, "strict"
		}, Flags{}, nil, "profile=strict", func(t *testing.T, eff *Effective, _ []Violation) {
			wantSetting(t, eff, "profile", "strict", SourceAdmin, "openshell.admin.min_profile")
		}},
		{"yolo off clamps the pack silently", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) }, Flags{}, nil,
			"yolo=false", func(t *testing.T, eff *Effective, _ []Violation) {
				wantSetting(t, eff, "yolo", "false", SourceAdmin, "openshell.admin.allow_yolo")
			}},
		{"yolo off refuses the user", func(o *config.OpenShellConfig) { o.Yolo, o.Admin.AllowYolo = boolPtr(true), boolPtr(false) }, Flags{},
			[]Violation{{Key: "yolo", Source: SourceUser, Enforced: "false", Constraint: "openshell.admin.allow_yolo"}}, "yolo=false", nil},
		{"yolo off refuses a flag", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) }, Flags{Yolo: true},
			[]Violation{{Key: "yolo", Source: SourceFlag}}, "yolo=false", nil},
		{"yolo off accepts --safe", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) }, Flags{Safe: true}, nil, "yolo=false", nil},
		{"yolo off refuses a chosen pack's default", func(o *config.OpenShellConfig) { o.Pack, o.Admin.AllowYolo = "open", boolPtr(false) }, Flags{},
			[]Violation{{Key: "yolo", Source: SourcePack}}, "yolo=false", nil},
		{"mounts off", func(o *config.OpenShellConfig) { o.Workdir.Mode, o.Admin.AllowMount = "mount", boolPtr(false) }, Flags{},
			[]Violation{{Key: "workdir.mode", Constraint: "openshell.admin.allow_mount"}}, "mode=copy", nil},
		{"mounts off accepts --copy", func(o *config.OpenShellConfig) { o.Admin.AllowMount = boolPtr(false) }, Flags{Copy: true}, nil,
			"mode=copy", func(t *testing.T, eff *Effective, _ []Violation) {
				wantSetting(t, eff, "workdir.mode", "copy", SourceFlag, "--copy")
			}},
		{"require copy for a project", func(o *config.OpenShellConfig) { o.Pack, o.Admin.RequireCopyFor = "open", []string{"/src/customer-*"} },
			Flags{Project: "/src/customer-acme/app"},
			[]Violation{{Key: "workdir.mode", Source: SourcePack, Constraint: "openshell.admin.require_copy_for", Detail: "/src/customer-*"}}, "mode=copy", nil},
		{"require copy elsewhere", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-*"} },
			Flags{Project: "/src/internal/app"}, nil, "mode=mount", nil},
		{"unblock off keeps the feed", func(o *config.OpenShellConfig) { o.Egress.Feed, o.Admin.AllowUnblock = "none", boolPtr(false) }, Flags{},
			[]Violation{{Key: "egress.feeds", Enforced: FeedBuiltin}}, "feeds=" + FeedBuiltin, nil},
		{"unblock off drops user allow entries", func(o *config.OpenShellConfig) {
			o.Pack, o.Egress.Allow, o.Admin.AllowUnblock = "balanced", []string{"paste.example"}, boolPtr(false)
		}, Flags{}, []Violation{{Key: "egress.allow", Attempted: "paste.example"}}, "", func(t *testing.T, eff *Effective, _ []Violation) {
			if containsString(eff.Egress.Allow, "paste.example") || !containsString(eff.Egress.Allow, "pypi.org") {
				t.Fatalf("allow %v", eff.Egress.Allow)
			}
			if got, _ := eff.Setting("egress.allow"); got.Source != SourceAdmin || !strings.Contains(got.Requested, "paste.example") {
				t.Fatalf("setting %+v", got)
			}
		}},
		{"admin blocklist is merged", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.Ngrok.io", "*.ngrok.io"} }, Flags{}, nil,
			"", func(t *testing.T, eff *Effective, _ []Violation) {
				if !reflect.DeepEqual(eff.Egress.AdminBlock, []string{"*.ngrok.io"}) {
					t.Fatalf("admin block %v", eff.Egress.AdminBlock)
				}
				wantSetting(t, eff, "egress.admin_block", "*.ngrok.io", SourceAdmin, "")
			}},
		// #946: a host name on the administrator's blocklist resolves to the
		// host and its "*." wildcard, once; addresses, ranges and wildcards
		// are kept, and the user's block list and the allow-only list are
		// not widened.
		{"admin blocklist domains cover subdomains", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"Example.NET.", "*.example.net", "ngrok.io", "203.0.113.7", "198.51.100.0/24"}
			o.Admin.EgressAllowOnly = []string{"example.com", "*.pypi.org"}
			o.Egress.Block = []string{"paste.example"}
		}, Flags{}, nil, "", func(t *testing.T, eff *Effective, _ []Violation) {
			want := []string{"example.net", "*.example.net", "ngrok.io", "*.ngrok.io", "203.0.113.7", "198.51.100.0/24"}
			if !reflect.DeepEqual(eff.Egress.AdminBlock, want) {
				t.Fatalf("admin block %v, want %v", eff.Egress.AdminBlock, want)
			}
			wantSetting(t, eff, "egress.admin_block", strings.Join(want, ", "), SourceAdmin, "openshell.admin.egress_block")
			if !reflect.DeepEqual(eff.Egress.AllowOnly, []string{"example.com", "*.pypi.org"}) || !containsString(eff.Egress.Block, "paste.example") ||
				containsString(eff.Egress.Block, "*.paste.example") {
				t.Fatalf("allow only %v, block %v", eff.Egress.AllowOnly, eff.Egress.Block)
			}
		}},
		{"host ports off", func(o *config.OpenShellConfig) { o.MCP.HostPorts, o.Admin.AllowHostPorts = []int{5432}, boolPtr(false) },
			Flags{HostPorts: []int{6379}},
			[]Violation{{Source: SourceUser, Constraint: "openshell.admin.allow_host_ports"}, {Source: SourceFlag, Constraint: "openshell.admin.allow_host_ports"}},
			"host_port_access=false host_ports=", func(t *testing.T, eff *Effective, _ []Violation) {
				wantSetting(t, eff, "mcp.host_port_access", "false", SourceAdmin, "")
				wantClamped(t, eff, "mcp.host_ports", "(none)", "5432, 6379", "")
			}},
		{"strict pack refuses host ports", func(o *config.OpenShellConfig) { o.Pack, o.MCP.HostPorts = "strict", []int{5432} }, Flags{},
			[]Violation{{Key: "mcp.host_ports", Constraint: "pack strict"}}, "host_ports=", func(t *testing.T, eff *Effective, violations []Violation) {
				if violations[0].Message != "not allowed by the strict sandbox pack: mcp.host_ports" {
					t.Fatalf("message %q", violations[0].Message)
				}
				wantSetting(t, eff, "mcp.host_ports", "(none)", SourcePack, "pack strict")
			}},
		{"resource ceilings", func(o *config.OpenShellConfig) {
			o.Resources.CPU = "4"
			o.Admin.MaxResources = config.OpenShellResourcesConfig{CPU: "2", Memory: "8Gi"}
		}, Flags{}, []Violation{{Key: "resources.cpu", Attempted: "4", Enforced: "2", Detail: "cpu at 2"}}, "cpu=2 memory=8Gi",
			func(t *testing.T, eff *Effective, _ []Violation) {
				wantClamped(t, eff, "resources.memory", "8Gi", "(unlimited)", "")
			}},
		{"resource flag over the ceiling", func(o *config.OpenShellConfig) { o.Admin.MaxResources = config.OpenShellResourcesConfig{Memory: "8Gi"} },
			Flags{Memory: "16G", CPU: "1500m"}, []Violation{{Key: "resources.memory", Source: SourceFlag}}, "cpu=1500m memory=8Gi", nil},
		{"resource within the ceiling", func(o *config.OpenShellConfig) {
			o.Resources.Memory = "8G"
			o.Admin.MaxResources = config.OpenShellResourcesConfig{Memory: "8Gi"}
		}, Flags{}, nil, "memory=8G", nil},
		{"harness outside the admin list", func(o *config.OpenShellConfig) { o.Admin.AllowedHarnesses = []string{"claude-code"} },
			Flags{Harness: "codex"}, []Violation{{Key: "harness", Source: SourceFlag, Constraint: "openshell.admin.allowed_harnesses", Fatal: true}},
			"harness=", func(t *testing.T, eff *Effective, _ []Violation) {
				if !reflect.DeepEqual(eff.AllowedHarnesses, []string{"claudecode"}) {
					t.Fatalf("allowed %v", eff.AllowedHarnesses)
				}
				wantSetting(t, eff, "harness", "(refused: codex)", SourceAdmin, "")
			}},
		{"harness on the admin list", func(o *config.OpenShellConfig) { o.Admin.AllowedHarnesses = []string{"claude-code", "codex"} },
			Flags{Harness: "claude_code"}, nil, "harness=claudecode", nil},
		{"learn mode off", func(o *config.OpenShellConfig) { o.Admin.AllowLearnMode = boolPtr(false) }, Flags{Learn: true},
			[]Violation{{Key: "learn", Source: SourceFlag}}, "learn=false", func(t *testing.T, eff *Effective, _ []Violation) {
				wantSetting(t, eff, "learn", "false", SourceAdmin, "openshell.admin.allow_learn_mode")
			}},
		{"permissive switches change nothing", func(o *config.OpenShellConfig) {
			o.Admin.AllowYolo, o.Admin.AllowMount, o.Admin.AllowHostPorts = boolPtr(true), boolPtr(true), boolPtr(true)
			o.Admin.AllowUnblock, o.Admin.AllowLearnMode = boolPtr(true), boolPtr(true)
			o.MCP.HostPorts = []int{5432}
		}, Flags{Learn: true}, nil, "yolo=true mode=mount learn=true host_ports=5432", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, testConfig(tc.user), tc.flags)
			wantViolations(t, violations, tc.want...)
			wantPosture(t, eff, tc.posture)
			if tc.check != nil {
				tc.check(t, eff, violations)
			}
		})
	}
}

// A gateway whose compute driver mounts no host folders runs every project
// on a copy. Explain names the driver, not the administrator, as the
// source; a mount the user chose is reported, the default pack's is not,
// and the driver's clamp is the only one when the administrator's would
// clamp too.
func TestResolveComputeDriverClamp(t *testing.T) {
	const why = "the OpenShell MicroVM (vm) driver mounts no host folders"
	for _, tc := range []struct {
		name  string
		user  func(*config.OpenShellConfig)
		flags Flags
		want  []Violation
	}{
		{"the default pack's mount", nil, Flags{}, nil},
		{"a mount the user chose", func(o *config.OpenShellConfig) { o.Workdir.Mode = "mount" }, Flags{},
			[]Violation{{Key: "workdir.mode", Source: SourceUser, Attempted: "mount", Enforced: "copy", Constraint: ConstraintComputeDriver, Detail: why}}},
		{"mounts off too", func(o *config.OpenShellConfig) { o.Workdir.Mode, o.Admin.AllowMount = "mount", boolPtr(false) }, Flags{},
			[]Violation{{Key: "workdir.mode", Constraint: ConstraintComputeDriver}}},
		{"copy required for the project too", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/*"} },
			Flags{Project: "/src/app"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := tc.flags
			flags.MountUnsupported = why
			eff, violations := mustResolve(t, testConfig(tc.user), flags)
			wantViolations(t, violations, tc.want...)
			wantPosture(t, eff, "mode=copy")
			got, _ := eff.Setting("workdir.mode")
			if got.Value != "copy" || got.Source != SourceGateway || got.Origin != ConstraintComputeDriver || got.Requested != "mount" {
				t.Fatalf("setting = %+v, want copy clamped from mount by the compute driver", got)
			}
			for _, v := range violations {
				if v.Admin() || strings.Contains(v.Message, "organization") || v.Fatal {
					t.Fatalf("the driver's clamp reads as the organization's: %+v", v)
				}
			}
		})
	}
	// --copy asks for what the driver can do: nothing is clamped.
	eff, violations := mustResolve(t, testConfig(nil), Flags{Copy: true, MountUnsupported: why})
	wantViolations(t, violations)
	wantSetting(t, eff, "workdir.mode", "copy", SourceFlag, "--copy")
	// A driver that mounts host folders changes nothing.
	eff, _ = mustResolve(t, testConfig(nil), Flags{})
	wantSetting(t, eff, "workdir.mode", "mount", SourcePack, "")
}

func TestResolvePackHarnessAllowlist(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "claude-only", strings.Replace(customPack("claude-only"),
		"harness: {yolo: true}", "harness: {yolo: true, allowed: [claudecode, codex]}", 1))
	cfg := testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "claude-only", root })

	eff, violations := mustResolve(t, cfg, Flags{Harness: "amp"})
	v := FirstFatal(violations)
	if v == nil || v.Constraint != "pack claude-only" || v.Message != "not allowed by the claude-only sandbox pack: harness" {
		t.Fatalf("violations %+v", violations)
	}
	wantSetting(t, eff, "harness", "(refused: amp)", SourcePack, "pack claude-only")
	wantSetting(t, eff, "harness.allowed", "claudecode, codex", SourcePack, "")

	cfg.OpenShell.Admin.AllowedHarnesses = []string{"codex", "opencode"}
	eff, violations = mustResolve(t, cfg, Flags{Harness: "claudecode"})
	if v := FirstFatal(violations); v == nil || v.Constraint != "openshell.admin.allowed_harnesses" {
		t.Fatalf("violations %+v", violations)
	}
	if !reflect.DeepEqual(eff.AllowedHarnesses, []string{"codex"}) {
		t.Fatalf("allowed = %v", eff.AllowedHarnesses)
	}
	wantSetting(t, eff, "harness.allowed", "codex", SourceAdmin, "pack claude-only ∩ openshell.admin.allowed_harnesses")
	if _, violations = mustResolve(t, cfg, Flags{Harness: "codex"}); len(violations) != 0 {
		t.Fatalf("codex violations %+v", violations)
	}

	// An empty intersection allows no harness, and JSON consumers can tell
	// it apart from "every harness".
	allowedJSON := func(eff *Effective) string {
		t.Helper()
		data, err := json.Marshal(eff)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Any     *bool     `json:"any_harness"`
			Allowed *[]string `json:"allowed_harnesses"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Any == nil || decoded.Allowed == nil || *decoded.Allowed == nil {
			t.Fatalf("json lacks any_harness or an allowed_harnesses array: %s", data)
		}
		return fmt.Sprintf("any=%v allowed=%v", *decoded.Any, *decoded.Allowed)
	}
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"opencode"}
	eff, violations = mustResolve(t, cfg, Flags{Harness: "codex"})
	if v := FirstFatal(violations); v == nil || eff.AnyHarness || len(eff.AllowedHarnesses) != 0 {
		t.Fatalf("empty intersection: violations %+v any %v allowed %v", violations, eff.AnyHarness, eff.AllowedHarnesses)
	}
	wantSetting(t, eff, "harness.allowed", "(none)", SourceAdmin, "")
	for _, harness := range []string{"claudecode", "codex", "opencode"} {
		if err := eff.Allow(Action{Kind: ActionHarness, Harness: harness}); err == nil {
			t.Fatalf("empty intersection allowed %s", harness)
		}
	}
	if got := allowedJSON(eff); got != "any=false allowed=[]" {
		t.Fatalf("empty intersection json: %s", got)
	}
	unrestricted, _ := mustResolve(t, testConfig(nil), Flags{})
	if got := allowedJSON(unrestricted); got != "any=true allowed=[]" {
		t.Fatalf("unrestricted json: %s", got)
	}
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
	restricted, _ := mustResolve(t, cfg, Flags{})
	if got := allowedJSON(restricted); got != "any=false allowed=[codex]" {
		t.Fatalf("restricted json: %s", got)
	}
}

// lockedViolations maps each openshell.admin.locked violation's key to its
// attempted flags, failing on any other violation.
func lockedViolations(t *testing.T, violations []Violation) map[string]string {
	t.Helper()
	attempted := map[string]string{}
	for _, v := range violations {
		if v.Constraint != "openshell.admin.locked" || v.Source != SourceFlag ||
			v.Message != "blocked by your organization's DefenseClaw policy: "+v.Key ||
			!strings.HasSuffix(v.Detail, "the run uses the configured value") {
			t.Fatalf("violation %+v", v)
		}
		attempted[v.Key] = v.Attempted
	}
	return attempted
}

func TestResolveLockedFlagsRefuseLoosening(t *testing.T) {
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.Profile, o.Yolo = "balanced", "balanced", boolPtr(false)
		o.Resources = config.OpenShellResourcesConfig{CPU: "2", Memory: "4Gi"}
		o.MCP.HostPorts = []int{5432}
		o.Admin.Locked = append([]string(nil), config.OpenShellLockableKeys...)
	})
	flags := Flags{
		Pack: "open", Profile: "open", Yolo: true, Unmask: []string{".env", ".env.example"},
		HostPorts: []int{5432, 6379}, CPU: "4", Memory: "4Gi", Harness: "codex", Learn: true,
	}
	eff, violations := mustResolve(t, cfg, flags)
	want := map[string]string{
		"pack": "--pack open", "profile": "--profile open", "yolo": "--yolo", "workdir.unmask": "--unmask .env",
		"mcp.host_ports": "--host-port 6379", "resources": "--cpu 4",
	}
	if got := lockedViolations(t, violations); !reflect.DeepEqual(got, want) {
		t.Fatalf("locked violations = %v, want %v", got, want)
	}
	for _, v := range violations {
		if v.Key == "pack" && !strings.Contains(v.Detail, "the open pack is looser than the configured balanced pack in network.mode") {
			t.Fatalf("pack violation detail %q", v.Detail)
		}
	}
	// Locked values hold; entries the configuration already has, and
	// unlockable inputs, apply.
	wantPosture(t, eff, "pack=balanced profile=balanced yolo=false host_ports=5432 cpu=2 memory=4Gi harness=codex learn=true")
	if containsString(eff.Workspace.Unmask, ".env") || !containsString(eff.Workspace.Unmask, ".env.example") {
		t.Fatalf("unmask %v", eff.Workspace.Unmask)
	}

	// Only locked keys are held; --yolo matching the configured value is
	// no loosening.
	cfg.OpenShell.Admin.Locked = []string{"yolo"}
	cfg.OpenShell.Yolo = boolPtr(true)
	eff, violations = mustResolve(t, cfg, Flags{Yolo: true, Pack: "open"})
	wantViolations(t, violations)
	wantPosture(t, eff, "yolo=true pack=open")
}

func TestResolveLockedFlagsAcceptTightening(t *testing.T) {
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.Yolo = "open", boolPtr(true)
		o.Resources.CPU = "2"
		o.Admin.Locked = append([]string(nil), config.OpenShellLockableKeys...)
	})
	for _, tc := range []struct {
		name    string
		flags   Flags
		posture string
	}{
		{"--safe", Flags{Safe: true}, "yolo=false"},
		{"--safe with --yolo", Flags{Safe: true, Yolo: true}, "yolo=false"},
		{"--copy", Flags{Copy: true}, "mode=copy"},
		{"--no-mcp", Flags{NoMCP: true}, "import=false"},
		{"stricter --profile", Flags{Profile: "strict"}, "profile=strict"},
		{"same --profile", Flags{Profile: "open"}, "profile=open"},
		{"stricter built-in --pack", Flags{Pack: "balanced"}, "pack=balanced"},
		// openshell.yolo still applies over the chosen pack.
		{"strictest built-in --pack", Flags{Pack: "strict"}, "pack=strict profile=strict yolo=true mode=copy"},
		{"same --pack", Flags{Pack: "open"}, "pack=open"},
		{"--pack and --profile", Flags{Pack: "strict", Profile: "balanced"}, "pack=strict profile=balanced"},
		{"lower --cpu and a --memory limit", Flags{CPU: "500m", Memory: "1Gi"}, "cpu=500m memory=1Gi"},
		{"configured --unmask", Flags{Unmask: []string{".env.example"}}, "unmask=.env.example,.env.sample,.env.template,.env.dist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, cfg, tc.flags)
			wantViolations(t, violations)
			wantPosture(t, eff, tc.posture)
		})
	}

	// A stricter pack is measured against the configured one: balanced is
	// looser than a configured strict.
	cfg.OpenShell.Pack = "strict"
	eff, violations := mustResolve(t, cfg, Flags{Pack: "balanced", Profile: "balanced"})
	if got := lockedViolations(t, violations); len(got) != 2 || got["pack"] != "--pack balanced" || got["profile"] != "--profile balanced" {
		t.Fatalf("violations %+v", violations)
	}
	wantPosture(t, eff, "pack=strict profile=strict")
	// A malformed request is an error, not a silently dropped flag.
	if _, _, err := Resolve(cfg, Flags{CPU: "lots"}); err == nil || !strings.Contains(err.Error(), "--cpu") {
		t.Fatalf("malformed locked --cpu: %v", err)
	}
}

func TestResolveLockedCustomPacks(t *testing.T) {
	root := t.TempDir()
	base := strings.Replace(customPack("base"), "network: {mode: open}",
		"network: {mode: allowlist}\negress: {allow: [git.corp.example, '*.pkg.corp.example'], block: [paste.example], large_upload_mb: 10}", 1)
	writePack(t, root, "base", base)
	variant := func(name, old, replacement string) {
		t.Helper()
		body := strings.Replace(strings.Replace(base, "name: base", "name: "+name, 1), old, replacement, 1)
		if body == strings.Replace(base, "name: base", "name: "+name, 1) {
			t.Fatalf("variant %s did not change the pack", name)
		}
		writePack(t, root, name, body)
	}
	variant("narrower", "allow: [git.corp.example, '*.pkg.corp.example']", "allow: [npm.pkg.corp.example, pypi.org]")
	variant("wider-allow", "allow: [git.corp.example, '*.pkg.corp.example']", "allow: [git.corp.example, api.example.net]")
	variant("fewer-blocks", "block: [paste.example]", "block: []")
	variant("broader-blocks", "block: [paste.example]", "block: ['*.example']")
	variant("no-upload-alert", "large_upload_mb: 10", "large_upload_mb: 0")
	variant("yolo-off", "harness: {yolo: true}", "harness: {yolo: false}")
	variant("host-ports", "mcp: {import: true, host_ports: false}", "mcp: {import: true, host_ports: true}")
	variant("deny-wider-allow", "mode: allowlist}\negress: {allow: [git.corp.example, '*.pkg.corp.example']",
		"mode: deny}\negress: {allow: [git.corp.example, api.example.net]")

	for _, tc := range []struct {
		pack, profile string
		looser        string // the key the refusal names, or "" when accepted
	}{
		{"narrower", "", ""},
		{"broader-blocks", "", ""},
		{"yolo-off", "", ""},
		{"strict", "", ""},
		{"wider-allow", "", "egress.allow"},
		{"fewer-blocks", "", "egress.block"},
		{"no-upload-alert", "", "egress.large_upload_mb"},
		{"host-ports", "", "mcp.host_ports"},
		{"open", "", "network.mode"},
		// With the proxy off the egress lists do not apply, unless the
		// user's profile turns the proxy back on.
		{"deny-wider-allow", "", ""},
		{"deny-wider-allow", "balanced", "egress.allow"},
	} {
		t.Run(tc.pack+"/"+tc.profile, func(t *testing.T) {
			cfg := testConfig(func(o *config.OpenShellConfig) {
				o.Pack, o.PackDir, o.Profile = "base", root, tc.profile
				o.Admin.Locked = []string{"pack"}
			})
			eff, violations := mustResolve(t, cfg, Flags{Pack: tc.pack})
			if tc.looser == "" {
				wantViolations(t, violations)
				wantPosture(t, eff, "pack="+tc.pack)
				return
			}
			wantViolations(t, violations, Violation{Key: "pack", Constraint: "openshell.admin.locked", Detail: "in " + tc.looser + ";"})
			wantPosture(t, eff, "pack=base")
		})
	}

	writePack(t, root, "masked", strings.Replace(customPack("masked"), "workspace: {mode: mount}",
		"workspace: {mode: mount, masks: [.env, .env.*]}", 1))
	for configured, tc := range map[string]struct{ pack, detail string }{
		// A pack that shares files the configured pack masks is looser.
		"masked": {"strict", "in workspace.unmask;"},
		// A pack that does not load is refused, and the configured pack runs.
		"base": {"missing-pack", "could not be loaded"},
	} {
		eff, violations := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
			o.Pack, o.PackDir, o.Admin.Locked = configured, root, []string{"pack"}
		}), Flags{Pack: tc.pack})
		wantViolations(t, violations, Violation{Key: "pack", Constraint: "openshell.admin.locked", Detail: tc.detail})
		wantPosture(t, eff, "pack="+configured)
	}
}

func TestLooserPackKeyBuiltins(t *testing.T) {
	load := func(name string) *Pack {
		pack, err := Builtin(name)
		if err != nil {
			t.Fatal(err)
		}
		return pack
	}
	open, balanced, strict := load("open"), load("balanced"), load("strict")
	// Letting a repository's MCP servers start is looser than blocking them;
	// a tamper response of alert is looser than stop, and stop never is.
	allowing := *open
	allowing.Name, allowing.MCP.ProjectServers = "allowing", MCPProjectServersAllow
	alerting := *balanced
	alerting.Name, alerting.Hooks.OnTamper = "alerting", OnTamperAlert
	stopping := *open
	stopping.Name, stopping.Hooks.OnTamper = "stopping", OnTamperStop
	// Reporting a large upload without cutting it is looser than blocking it.
	blocking := *open
	blocking.Name, blocking.Egress.BlockLargeUploads = "blocking", true
	for _, tc := range []struct {
		candidate, baseline *Pack
		want                string
	}{
		{balanced, open, ""},
		{strict, open, ""},
		{strict, balanced, ""},
		{open, open, ""},
		{open, balanced, "network.mode"},
		{balanced, strict, "network.mode"},
		{&allowing, open, "mcp.project_servers"},
		{open, &allowing, ""},
		{&alerting, balanced, "hooks.on_tamper"},
		{balanced, &alerting, ""},
		{&stopping, open, ""},
		{open, &blocking, "egress.block_large_uploads"},
		{&blocking, open, ""},
	} {
		if got := looserPackKey(tc.candidate, tc.baseline, tc.candidate.Network.Mode); got != tc.want {
			t.Errorf("looserPackKey(%s, %s) = %q, want %q", tc.candidate.Name, tc.baseline.Name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		outer, inner string
		want         bool
	}{
		{"*", "*.example.com", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "*.a.example.com", true},
		{"*.Example.com.", "A.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "*", false},
		{"a.example.com", "*.a.example.com", false},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"2001:db8::1", "2001:0db8:0:0::1", true},
		{"203.0.113.7", "::ffff:203.0.113.7", true},
		{"198.51.100.0/24", "198.51.100.7", true},
		{"198.51.100.0/24", "198.51.100.128/25", true},
		{"198.51.100.128/25", "198.51.100.0/24", false},
		{"198.51.100.0/24", "*.example.com", false},
		{"*.example.com", "198.51.100.7", false},
	} {
		if got := hostGlobCovers(tc.outer, tc.inner); got != tc.want {
			t.Errorf("hostGlobCovers(%q, %q) = %v, want %v", tc.outer, tc.inner, got, tc.want)
		}
	}
}

func TestResolveRequiredPack(t *testing.T) {
	root := t.TempDir()
	corpDir := writePack(t, root, "corp", strings.Replace(customPack("corp"), "harness: {yolo: true}", "harness: {yolo: true, allowed: [codex]}", 1))
	requiredOver := func(pack string, edit func(*config.OpenShellConfig)) func(*config.OpenShellConfig) {
		return func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.RequiredPack = pack, "strict"
			if edit != nil {
				edit(o)
			}
		}
	}
	const constraint = "openshell.admin.required_pack"
	for _, tc := range []struct {
		name    string
		edit    func(*config.OpenShellConfig)
		flags   Flags
		want    []Violation
		posture string
	}{
		{"another pack by the user", requiredOver("open", nil), Flags{},
			[]Violation{{Key: "pack", Source: SourceUser, Attempted: "open", Enforced: "strict", Constraint: constraint}},
			"pack=strict yolo=false mode=copy"},
		{"another pack by a flag", requiredOver("open", nil), Flags{Pack: "balanced"},
			[]Violation{{Key: "pack", Source: SourceFlag, Attempted: "balanced", Constraint: constraint}}, "pack=strict"},
		{"the required pack", requiredOver("strict", nil), Flags{}, nil, "pack=strict"},
		// The required pack's profile is a floor for flags.
		{"a looser --profile", requiredOver("strict", nil), Flags{Profile: "open"},
			[]Violation{{Key: "profile", Source: SourceFlag, Attempted: "open", Enforced: "strict", Constraint: constraint, Detail: "requires the strict sandbox pack"}},
			"profile=strict"},
		{"a locked profile", requiredOver("strict", func(o *config.OpenShellConfig) { o.Admin.Locked = []string{"profile"} }), Flags{Profile: "open"},
			[]Violation{{Key: "profile", Constraint: "openshell.admin.locked"}}, "profile=strict"},
		{"min_profile over a required pack", requiredOver("strict", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "strict" }),
			Flags{Profile: "balanced"}, []Violation{{Constraint: "openshell.admin.min_profile"}}, "profile=strict"},
		// The same content under another reference is not a loosening, and a
		// required pack's own values are not the user's attempts.
		{"the same pack by path", func(o *config.OpenShellConfig) {
			o.PackDir, o.Pack, o.Admin.RequiredPack, o.Admin.AllowYolo = root, "corp", corpDir, boolPtr(false)
		}, Flags{Harness: "codex"}, nil, "pack=corp yolo=false"},
		{"a missing --pack", func(o *config.OpenShellConfig) {
			o.PackDir, o.Pack, o.Admin.RequiredPack = root, "corp", corpDir
		}, Flags{Pack: "missing-pack"}, []Violation{{Key: "pack", Attempted: "missing-pack"}}, "pack=corp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, testConfig(tc.edit), tc.flags)
			wantViolations(t, violations, tc.want...)
			wantPosture(t, eff, tc.posture)
			if len(tc.want) > 0 && tc.want[0].Constraint == constraint {
				wantClamped(t, eff, tc.want[0].Key, "strict", tc.want[0].Attempted, "")
			}
		})
	}
	cfg := testConfig(func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "no-such-pack" })
	if _, _, err := Resolve(cfg, Flags{}); err == nil || !strings.Contains(err.Error(), "openshell.admin.required_pack") {
		t.Fatalf("missing required pack: %v", err)
	}
}

// A required pack's posture is a floor: user keys and flags may tighten it
// but every loosening is clamped and reported.
func TestResolveRequiredPackFloors(t *testing.T) {
	const constraint = "openshell.admin.required_pack"
	loosen := func(o *config.OpenShellConfig) {
		o.Admin.RequiredPack = "strict"
		o.Profile, o.Yolo, o.Workdir.Mode = "open", boolPtr(true), "mount"
		o.MCP.Import = boolPtr(true)
		o.Egress.Feed, o.Egress.Ports = "none", []int{22, 443}
	}
	eff, violations := mustResolve(t, testConfig(loosen), Flags{})
	enforced := map[string]string{}
	for _, v := range violations {
		if v.Constraint != constraint || v.Source != SourceUser || v.Message != "blocked by your organization's DefenseClaw policy: "+v.Key {
			t.Fatalf("violation %+v", v)
		}
		enforced[v.Key] = v.Enforced
	}
	want := map[string]string{
		"profile": "strict", "yolo": "false", "workdir.mode": "copy", "mcp.import": "false",
		"egress.feeds": FeedBuiltin, "egress.ports": "443",
	}
	if len(violations) != len(want) || !reflect.DeepEqual(enforced, want) {
		t.Fatalf("violations = %+v, want %v enforced", violations, want)
	}
	wantPosture(t, eff, "profile=strict network="+NetworkDeny+" yolo=false mode=copy import=false feeds="+FeedBuiltin+" ports=443")
	wantSetting(t, eff, "egress.ports", "443", SourceAdmin, constraint)

	// Flags are clamped the same way.
	eff, violations = mustResolve(t, testConfig(required("strict")), Flags{Profile: "balanced", Yolo: true})
	wantViolations(t, violations, Violation{Source: SourceFlag, Constraint: constraint}, Violation{Source: SourceFlag, Constraint: constraint})
	wantPosture(t, eff, "profile=strict yolo=false")

	// Only ports outside the pack are dropped; with none left the pack's
	// ports apply.
	eff, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Admin.RequiredPack, o.Egress.Ports = "balanced", []int{8443}
	}), Flags{})
	wantViolations(t, violations, Violation{Key: "egress.ports", Attempted: "8443", Constraint: constraint})
	wantPosture(t, eff, "ports=80,443")

	// Tightening a required pack is not a violation.
	eff, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Admin.RequiredPack, o.Egress.Ports, o.Egress.Feed = "balanced", []int{443}, "builtin"
	}), Flags{Profile: "strict", Safe: true, Copy: true, NoMCP: true})
	wantViolations(t, violations)
	wantPosture(t, eff, "profile=strict yolo=false mode=copy import=false ports=443")
	// Without required_pack the same choices over the pack are the user's.
	_, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		loosen(o)
		o.Admin.RequiredPack, o.Pack = "", "strict"
	}), Flags{})
	wantViolations(t, violations)
}

// A deny-mode pack may list no ports. Under a profile that runs the proxy
// it gets the default ports, the ones the proxy's decider relays for an
// empty list, so the effective list, DecideEgress and the decider agree;
// under its own profile the list stays empty.
func TestResolveDenyPackWithoutPortsUnderAProxyProfile(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "noports", strings.Replace(customPack("noports"), "network: {mode: open}",
		"network: {mode: deny}\negress: {ports: []}", 1))
	for _, tc := range []struct {
		profile string
		ports   []int
	}{
		{"open", []int{80, 443}},
		{"balanced", []int{80, 443}},
		{"", []int{}},
	} {
		t.Run("profile "+tc.profile, func(t *testing.T) {
			eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.PackDir = root }),
				Flags{Pack: "noports", Profile: tc.profile})
			if !reflect.DeepEqual(eff.Egress.Ports, tc.ports) {
				t.Fatalf("ports = %v, want %v", eff.Egress.Ports, tc.ports)
			}
			if eff.NetworkMode == NetworkDeny {
				wantSetting(t, eff, "egress.ports", "(none)", SourcePack, "pack noports")
				return
			}
			wantSetting(t, eff, "egress.ports", "80, 443", SourceDefault, "defenseclaw default (pack noports lists no ports)")
			d, err := eff.EgressDecider(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(d.Ports(), eff.Egress.Ports) {
				t.Fatalf("decider ports %v, effective ports %v", d.Ports(), eff.Egress.Ports)
			}
			if got := eff.DecideEgress("pypi.org", 443); got.Rule == RulePort {
				t.Fatalf("DecideEgress(pypi.org:443) = %+v", got)
			}
			if got := eff.DecideEgress("pypi.org", 8443); got.Rule != RulePort {
				t.Fatalf("DecideEgress(pypi.org:8443) = %+v, want the port refused", got)
			}
		})
	}
}

func TestResolveRequiredPackTrust(t *testing.T) {
	root := t.TempDir()
	corpDir := writePack(t, root, "corp", strings.Replace(customPack("corp"), "network: {mode: open}",
		"network: {mode: open}\negress: {feeds: []}", 1))
	corpFile := filepath.Join(corpDir, PackFileName)
	corp, err := LoadFile(corpDir)
	if err != nil {
		t.Fatal(err)
	}
	managedCfg := func(required string) *config.Config {
		cfg := testConfig(func(o *config.OpenShellConfig) { o.PackDir, o.Admin.RequiredPack = root, required })
		cfg.DeploymentMode = "managed_enterprise"
		return cfg
	}

	// A pack file the user owns cannot stand in for the administrator's.
	for _, ref := range []string{"corp", corpDir, corpFile} {
		if _, _, err := Resolve(managedCfg(ref), Flags{}); err == nil ||
			!strings.Contains(err.Error(), "openshell.admin.required_pack") || !strings.Contains(err.Error(), "administrator-owned") {
			t.Fatalf("user-owned required pack %q: %v", ref, err)
		}
	}

	if _, _, err := Resolve(managedCfg("missing-pack"), Flags{}); err == nil || !strings.Contains(err.Error(), "no such pack file") {
		t.Fatalf("missing managed required pack: %v", err)
	}

	var checked []string
	previous := validateTrustedFile
	validateTrustedFile = func(path, _ string) error {
		checked = append(checked, path)
		return nil
	}
	t.Cleanup(func() { validateTrustedFile = previous })
	eff, _ := mustResolve(t, managedCfg("corp"), Flags{})
	if eff.Pack.Name != "corp" || !reflect.DeepEqual(checked, []string{corpFile}) {
		t.Fatalf("pack %s checked %v", eff.Pack.Name, checked)
	}
	checked = nil
	if _, _ = mustResolve(t, managedCfg("strict"), Flags{}); len(checked) != 0 {
		t.Fatalf("a built-in pack was checked: %v", checked)
	}
	// Outside managed_enterprise the user owns config.yaml anyway.
	cfg := managedCfg("corp")
	cfg.DeploymentMode = ""
	if _, _ = mustResolve(t, cfg, Flags{}); len(checked) != 0 {
		t.Fatalf("advisory mode checked %v", checked)
	}

	// required_pack_digest pins the content in every mode.
	for _, mode := range []string{"", "managed_enterprise"} {
		cfg := managedCfg("corp")
		cfg.DeploymentMode = mode
		cfg.OpenShell.Admin.RequiredPackDigest = corp.Digest
		if eff, _ := mustResolve(t, cfg, Flags{}); eff.Pack.Digest != corp.Digest {
			t.Fatalf("digest %s", eff.Pack.Digest)
		}
		cfg.OpenShell.Admin.RequiredPackDigest = "sha256:" + strings.Repeat("0", 64)
		if _, _, err := Resolve(cfg, Flags{}); err == nil || !strings.Contains(err.Error(), "required_pack_digest") ||
			!strings.Contains(err.Error(), corp.Digest) {
			t.Fatalf("mode %q digest mismatch: %v", mode, err)
		}
	}
}

func TestResolveAllowList(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "team", strings.Replace(customPack("team"), "network: {mode: open}",
		"network: {mode: allowlist}\negress: {allow: [git.corp.example]}", 1))
	curated, err := Builtin("balanced")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		edit      func(*config.OpenShellConfig)
		flags     Flags
		has       []string
		lacks     []string
		curated   bool
		violation string // constraint of the only violation, or ""
		origin    string
	}{
		{"open pack", nil, Flags{}, nil, []string{"pypi.org"}, false, "", "pack open"},
		{"raised by a flag", nil, Flags{Profile: "balanced"}, nil, nil, true, "", "pack open + the curated allowlist of pack balanced"},
		{"raised by the admin", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" }, Flags{}, nil, nil, true, "", ""},
		{"lowered from strict", func(o *config.OpenShellConfig) { o.Pack = "strict" }, Flags{Profile: "balanced"}, nil, nil, true, "", ""},
		{"raised to strict", nil, Flags{Profile: "strict"}, nil, []string{"pypi.org"}, false, "", ""},
		{"custom allowlist pack keeps its own list", func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "team", root }, Flags{},
			[]string{"git.corp.example"}, []string{"pypi.org"}, false, "", "pack team"},
		{"user entries merge", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"API.Example.com"} }, Flags{Profile: "balanced"},
			[]string{"api.example.com"}, nil, true, "", "pack open + the curated allowlist of pack balanced + openshell.egress.allow"},
		{"broad user entries are ignored", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"*", "*.com", "api.example.com"} }, Flags{},
			[]string{"api.example.com"}, []string{"*", "*.com"}, false, "defenseclaw", ""},
		{"unblock off drops a chosen custom pack's entries", func(o *config.OpenShellConfig) {
			o.Pack, o.PackDir, o.Admin.AllowUnblock = "team", root, boolPtr(false)
		}, Flags{}, nil, []string{"git.corp.example"}, false, "openshell.admin.allow_unblock", ""},
		{"unblock off keeps a required pack's entries", func(o *config.OpenShellConfig) {
			o.PackDir, o.Admin.RequiredPack, o.Admin.AllowUnblock = root, "team", boolPtr(false)
		}, Flags{}, []string{"git.corp.example"}, []string{"pypi.org"}, false, "", "pack team"},
		{"unblock off keeps the curated entries", func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.AllowUnblock = "balanced", boolPtr(false)
		}, Flags{}, nil, nil, true, "", "pack balanced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, testConfig(tc.edit), tc.flags)
			switch {
			case tc.violation == "" && len(violations) != 0:
				t.Fatalf("violations = %+v", violations)
			case tc.violation != "":
				if v := onlyViolation(t, violations); v.Constraint != tc.violation || v.Key != "egress.allow" {
					t.Fatalf("violation = %+v", v)
				}
			}
			for _, host := range tc.has {
				if !containsString(eff.Egress.Allow, host) {
					t.Fatalf("allow %v lacks %s", eff.Egress.Allow, host)
				}
			}
			for _, host := range tc.lacks {
				if containsString(eff.Egress.Allow, host) {
					t.Fatalf("allow %v has %s", eff.Egress.Allow, host)
				}
			}
			for _, host := range curated.Egress.Allow {
				if containsString(eff.Egress.Allow, host) != tc.curated {
					t.Fatalf("curated %s present = %v, want %v (allow %v)", host, !tc.curated, tc.curated, eff.Egress.Allow)
				}
			}
			if tc.origin != "" {
				if got, _ := eff.Setting("egress.allow"); got.Origin != tc.origin {
					t.Fatalf("egress.allow provenance = %+v, want origin %q", got, tc.origin)
				}
			}
		})
	}

	// The reported bypass: a custom allowlist pack that allows every host
	// no longer loads.
	writePack(t, root, "wide", strings.Replace(customPack("wide"), "network: {mode: open}",
		"network: {mode: allowlist}\negress: {allow: ['*'], feeds: []}", 1))
	_, _, err = Resolve(testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.PackDir, o.Admin.MinProfile, o.Admin.AllowUnblock = "wide", root, "balanced", boolPtr(false)
	}), Flags{})
	if err == nil || !strings.Contains(err.Error(), "egress.allow[0]") {
		t.Fatalf("allow-everything pack: %v", err)
	}
}

func TestResolveRequireCopyWithoutProject(t *testing.T) {
	const constraint = "openshell.admin.require_copy_for"
	cfg := testConfig(func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} })
	eff, violations := mustResolve(t, cfg, Flags{})
	wantViolations(t, violations)
	wantSetting(t, eff, "workdir.mode", "copy", SourceAdmin, constraint)

	cfg.OpenShell.Workdir.Mode = "mount"
	eff, violations = mustResolve(t, cfg, Flags{})
	wantViolations(t, violations, Violation{Source: SourceUser, Constraint: constraint, Detail: "no project folder"})
	wantPosture(t, eff, "mode=copy")
	// The reported bypass: mounting the parent of a covered repository.
	eff, violations = mustResolve(t, cfg, Flags{Project: "/src"})
	wantViolations(t, violations, Violation{Constraint: constraint})
	wantPosture(t, eff, "mode=copy")
	// Without require_copy_for a missing project changes nothing.
	eff, _ = mustResolve(t, testConfig(nil), Flags{})
	wantPosture(t, eff, "mode=mount")
}

func TestResolveErrors(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "broken", "version: 1\n")
	for _, tc := range []struct {
		name  string
		cfg   *config.Config
		flags Flags
		want  string
	}{
		{"nil config", nil, Flags{}, "no configuration"},
		{"unknown profile flag", testConfig(nil), Flags{Profile: "wide"}, `--profile "wide"`},
		{"relative project", testConfig(nil), Flags{Project: "src/app"}, "must be absolute"},
		{"host port range", testConfig(nil), Flags{HostPorts: []int{70000}}, "--host-port 70000"},
		{"harness name", testConfig(nil), Flags{Harness: "claude code"}, "invalid harness name"},
		{"unmask flag escapes the project", testConfig(nil), Flags{Unmask: []string{".env", "../../secrets/app.key"}}, `--unmask: "../../secrets/app.key"`},
		{"absolute unmask flag", testConfig(nil), Flags{Unmask: []string{"/srv/app/.env"}}, "--unmask"},
		{"home unmask flag", testConfig(nil), Flags{Unmask: []string{"~/notes.txt"}}, "--unmask"},
		{"absolute user mask", testConfig(func(o *config.OpenShellConfig) { o.Workdir.Masks = []string{"/srv/app/.env"} }), Flags{}, "openshell.workdir.masks[0]"},
		{"escaping user unmask", testConfig(func(o *config.OpenShellConfig) { o.Workdir.Unmask = []string{"a/../../b"} }), Flags{}, "openshell.workdir.unmask[0]"},
		{"cpu flag", testConfig(nil), Flags{CPU: "lots"}, "--cpu"},
		{"memory config", testConfig(func(o *config.OpenShellConfig) { o.Resources.Memory = "4GB" }), Flags{}, "openshell.resources.memory"},
		{"missing pack flag", testConfig(nil), Flags{Pack: "nope"}, "--pack"},
		{"broken user pack", testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "broken", root }), Flags{}, "openshell.pack"},
		{"bad admin ceiling", testConfig(func(o *config.OpenShellConfig) { o.Admin.MaxResources.CPU = "x" }), Flags{}, "max_resources"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations, err := Resolve(tc.cfg, tc.flags)
			if err == nil || !strings.Contains(err.Error(), tc.want) || eff != nil || violations != nil {
				t.Fatalf("Resolve = %v, %v, %v; want an error containing %q", eff, violations, err, tc.want)
			}
		})
	}
}

func TestExplainProvenance(t *testing.T) {
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.Profile = "balanced"
		o.Admin.AllowYolo = boolPtr(false)
		o.Admin.EgressBlock = []string{"*.ngrok.io"}
	})
	eff, _ := mustResolve(t, cfg, Flags{Copy: true, Harness: "codex"})
	settings := eff.Explain()
	if len(settings) != len(explainOrder) {
		t.Fatalf("Explain() returned %d settings, want %d", len(settings), len(explainOrder))
	}
	sources := map[string]Source{}
	for i, setting := range settings {
		if setting.Key != explainOrder[i] || setting.Value == "" || setting.Origin == "" {
			t.Fatalf("setting %d = %+v", i, setting)
		}
		sources[setting.Key] = setting.Source
	}
	for key, want := range map[string]Source{
		"pack": SourceDefault, "profile": SourceUser, "yolo": SourceAdmin, "workdir.mode": SourceFlag,
		"harness": SourceFlag, "egress.admin_block": SourceAdmin, "egress.feeds": SourcePack,
		"workdir.git_depth": SourceDefault,
	} {
		if sources[key] != want {
			t.Fatalf("source of %s = %s, want %s", key, sources[key], want)
		}
	}
	data, err := json.Marshal(eff)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	pack := decoded["pack"].(map[string]any)
	if decoded["profile"] != "balanced" || pack["name"] != "open" || !strings.HasPrefix(pack["digest"].(string), "sha256:") {
		t.Fatalf("json = %s", data)
	}
}

func TestResolveReservedHostPorts(t *testing.T) {
	routed := func(port int, endpoint string) func(*config.Config) {
		return func(c *config.Config) {
			c.Routing.Enabled, c.Routing.Port, c.Routing.Remote.Endpoint = true, port, endpoint
		}
	}
	for _, tc := range []struct {
		name        string
		edit        func(*config.Config)
		gatewayPort int // Flags.OpenShellGatewayPort
		port        int
		what        string
	}{
		{"api", nil, 0, 18970, "DefenseClaw's API"},
		{"ingress", nil, 0, 18971, "sandbox hook ingress"},
		{"egress", nil, 0, 18972, "egress proxy"},
		{"default openshell gateway", nil, 0, OpenShellGatewayPort, "the OpenShell gateway"},
		{"registered openshell gateway", nil, 18080, 18080, "the OpenShell gateway"},
		{"guardrail proxy", nil, 0, 4000, "guardrail proxy"},
		{"default api port", func(c *config.Config) { c.Gateway.APIPort = 0 }, 0, 18970, "DefenseClaw's API"},
		{"custom ingress", func(c *config.Config) { c.OpenShell.IngressPort = 20001 }, 0, 20001, "sandbox hook ingress"},
		{"default openclaw gateway", nil, 0, 18789, "the OpenClaw gateway"},
		{"custom openclaw gateway", func(c *config.Config) { c.Gateway.Port = 28789 }, 0, 28789, "the OpenClaw gateway"},
		{"default model router", routed(0, ""), 0, 8080, "model router"},
		{"custom model router", routed(8801, ""), 0, 8801, "model router"},
		{"loopback remote router", routed(0, "http://127.0.0.1:8802"), 0, 8802, "model router"},
		{"localhost remote router", routed(0, "http://localhost"), 0, 80, "model router"},
		// Ports that are not listeners of this run stay available.
		{"default gateway port once the registration names another", nil, 18080, OpenShellGatewayPort, ""},
		{"router port while routing is off", nil, 0, 8080, ""},
		{"router port with a remote router", routed(0, "https://router.corp.example:8080"), 0, 8080, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(nil)
			if tc.edit != nil {
				tc.edit(cfg)
			}
			eff, violations := mustResolve(t, cfg, Flags{HostPorts: []int{tc.port, 5432}, OpenShellGatewayPort: tc.gatewayPort})
			if tc.what == "" {
				wantViolations(t, violations)
				wantPosture(t, eff, "host_ports="+strconv.Itoa(tc.port)+",5432")
				return
			}
			wantViolations(t, violations, Violation{Source: SourceFlag, Constraint: "defenseclaw"})
			if v := violations[0]; !strings.Contains(v.Message, tc.what) || !strings.HasPrefix(v.Message, "DefenseClaw never opens") {
				t.Fatalf("violation %+v", v)
			}
			wantPosture(t, eff, "host_ports=5432")
			if err := eff.Allow(Action{Kind: ActionHostPort, Port: tc.port}); err == nil {
				t.Fatalf("Allow(host port %d) = nil, want a refusal", tc.port)
			}
			if err := eff.Allow(Action{Kind: ActionApprove, Host: OpenShellHostAlias, Port: tc.port}); err == nil {
				t.Fatalf("approving %s:%d was allowed", OpenShellHostAlias, tc.port)
			}
		})
	}

	if _, _, err := Resolve(testConfig(nil), Flags{OpenShellGatewayPort: 70000}); err == nil ||
		!strings.Contains(err.Error(), "OpenShell gateway port 70000") {
		t.Fatalf("invalid registration port: %v", err)
	}
}

func TestAdminStatusFor(t *testing.T) {
	if got := AdminStatusFor(nil); got.Configured || got.Authority != AuthorityAdvisory {
		t.Fatalf("nil = %+v", got)
	}
	cfg := testConfig(nil)
	if got := AdminStatusFor(cfg); got.Configured || got.Authority != AuthorityAdvisory || got.Detail != "no openshell.admin constraints" {
		t.Fatalf("unconfigured = %+v", got)
	}
	cfg.OpenShell.Admin.MinProfile = "balanced"
	if got := AdminStatusFor(cfg); !got.Configured || got.Authority != AuthorityAdvisory || !strings.Contains(got.Detail, "advisory") {
		t.Fatalf("advisory = %+v", got)
	}
	cfg.DeploymentMode = "Managed_Enterprise"
	if got := AdminStatusFor(cfg); !got.Configured || got.Authority != AuthorityAuthoritative || !strings.Contains(got.Detail, "administrator-owned") {
		t.Fatalf("authoritative = %+v", got)
	}
	cfg.OpenShell.Admin = config.OpenShellAdminConfig{}
	if got := AdminStatusFor(cfg); got.Configured || got.Authority != AuthorityAuthoritative {
		t.Fatalf("managed without admin = %+v", got)
	}
	eff, _ := mustResolve(t, cfg, Flags{})
	if eff.Admin.Authority != AuthorityAuthoritative {
		t.Fatalf("Effective.Admin = %+v", eff.Admin)
	}
}

func TestRequireCopyForMatching(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	real := filepath.Join(home, "real", "customer-acme")
	if err := os.MkdirAll(filepath.Join(real, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "link")
	if err := os.Symlink(filepath.Join(home, "real"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for _, tc := range []struct {
		name, pattern, project string
		want                   bool
	}{
		{"exact dir covers itself", "/src/acme", "/src/acme", true},
		{"exact dir covers children", "/src/acme", "/src/acme/app/web", true},
		{"sibling prefix", "/src/acme", "/src/acme-internal", false},
		{"single-segment wildcard", "/src/customer-*", "/src/customer-x/app", true},
		{"wildcard does not cross segments", "/src/*/secret", "/src/a/b/secret", false},
		{"double star", "/src/**/secret", "/src/a/b/secret/app", true},
		{"double star matches zero segments", "/src/**/secret", "/src/secret", true},
		{"question mark", "/src/app?", "/src/app1", true},
		{"tilde", "~/real/customer-*", real, true},
		{"unclean pattern", "/src//acme/", "/src/acme/x", true},
		{"symlinked project spelling", filepath.Join(home, "real", "customer-*"), filepath.Join(link, "customer-acme", "app"), true},
		{"symlinked pattern prefix", filepath.Join(link, "customer-*"), filepath.Join(real, "app"), true},
		{"unrelated", "/src/acme", "/home/user/acme", false},
		{"empty pattern", " ", "/src/acme", false},
		{"parent of a covered dir", "/src/customer-acme", "/src", true},
		{"root covers everything", "/src/customer-acme", "/", true},
		{"home above a tilde pattern", "~/work/acme", home, true},
		{"parent of a wildcard match", "/src/customer-*", "/src", true},
		{"parent of a double star match", "/src/**/secret", "/src/a", true},
		{"parent of a double star match at the root", "/**/secret", "/", true},
		{"sibling of a covered dir", "/src/a/b", "/src/c", false},
		{"parent of a sibling", "/src/customer-*", "/home", false},
		{"pattern in another case", "/Src/Customer-ACME", "/src/customer-acme/app", true},
		{"project in another case", "/src/customer-*", "/SRC/CUSTOMER-X", true},
		{"parent in another case", "/src/customer-acme", "/SRC", true},
		// Config validation refuses relative and malformed patterns; a
		// programmatic config that has one errs toward copy mode.
		{"relative pattern matches at any depth", "customer-*", "/home/user/customer-acme/app", true},
		{"relative pattern with a wildcard parent", "*/customer-acme", "/home/user/customer-acme", true},
		{"relative pattern covers every mount", "customer-*", "/home/user/internal", true},
		{"malformed segment", "/src/customer-[", "/src/customer-x", true},
		{"malformed segment below the project", "/src/app/[", "/src/app", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff := &Effective{home: home, admin: config.OpenShellAdminConfig{RequireCopyFor: []string{tc.pattern}}}
			if got := eff.requiresCopy(tc.project) != ""; got != tc.want {
				t.Fatalf("requiresCopy(%q) under %q = %v, want %v", tc.project, tc.pattern, got, tc.want)
			}
		})
	}
	eff := &Effective{admin: config.OpenShellAdminConfig{RequireCopyFor: []string{"~/x"}}}
	if eff.requiresCopy("/x") != "" {
		t.Fatal("a tilde pattern without a home directory must not match")
	}
	if eff.requiresCopy("") != "" {
		t.Fatal("an empty path must not match (Resolve handles a missing project)")
	}
}

// TestResolveLockedKeysHoldAgainstPack: a --pack is checked against every
// locked key the pack decides, not only when "pack" itself is locked.
func TestResolveLockedKeysHoldAgainstPack(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "fewer-masks", strings.Replace(customPack("fewer-masks"), "network: {mode: open}",
		"network: {mode: deny}\negress: {ports: [443]}", 1))
	for _, tc := range []struct {
		name   string
		locked string
		edit   func(*config.OpenShellConfig)
		flags  Flags
		key    string // the refused key, or "" when the --pack applies
		detail string
	}{
		{"yolo", "yolo", nil, Flags{Pack: "open"}, "yolo", "in harness.yolo"},
		{"workdir.mode", "workdir.mode", nil, Flags{Pack: "open"}, "workdir.mode", "in workspace.mode"},
		{"mcp.import", "mcp.import", nil, Flags{Pack: "open"}, "mcp.import", "in mcp.import"},
		{"mcp.host_ports", "mcp.host_ports", nil, Flags{Pack: "open"}, "mcp.host_ports", "in mcp.host_ports"},
		{"profile", "profile", nil, Flags{Pack: "balanced"}, "profile", "in network.mode"},
		{"workdir.unmask", "workdir.unmask", func(o *config.OpenShellConfig) { o.PackDir = root }, Flags{Pack: "fewer-masks"},
			"workdir.unmask", "in workspace.masks"},
		// The user's own key, or a tightening flag, decides instead of the
		// pack, so the --pack loosens nothing locked.
		{"yolo set by the user", "yolo", func(o *config.OpenShellConfig) { o.Yolo = boolPtr(false) }, Flags{Pack: "open"}, "", ""},
		{"yolo with --safe", "yolo", nil, Flags{Pack: "open", Safe: true}, "", ""},
		{"workdir.mode with --copy", "workdir.mode", nil, Flags{Pack: "open", Copy: true}, "", ""},
		{"workdir.mode set by the user", "workdir.mode", func(o *config.OpenShellConfig) { o.Workdir.Mode = "copy" }, Flags{Pack: "open"}, "", ""},
		{"mcp.import with --no-mcp", "mcp.import", nil, Flags{Pack: "open", NoMCP: true}, "", ""},
		{"profile set by the user", "profile", func(o *config.OpenShellConfig) { o.Profile = "strict" }, Flags{Pack: "open"}, "", ""},
		{"profile with a stricter --profile", "profile", nil, Flags{Pack: "open", Profile: "strict"}, "", ""},
		{"workdir.unmask with the user's masks", "workdir.unmask", func(o *config.OpenShellConfig) {
			o.PackDir, o.Workdir.Masks = root, packMasks(t, "strict")
		}, Flags{Pack: "fewer-masks"}, "", ""},
		{"resources", "resources", nil, Flags{Pack: "open"}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(func(o *config.OpenShellConfig) {
				o.Pack, o.Admin.Locked = "strict", []string{tc.locked}
				if tc.edit != nil {
					tc.edit(o)
				}
			})
			eff, violations := mustResolve(t, cfg, tc.flags)
			if tc.key == "" {
				wantViolations(t, violations)
				wantPosture(t, eff, "pack="+tc.flags.Pack)
				return
			}
			if got := lockedViolations(t, violations); len(got) != 1 || got[tc.key] != "--pack "+tc.flags.Pack ||
				!strings.Contains(violations[0].Detail, "looser than the configured strict pack "+tc.detail) {
				t.Fatalf("locked violations = %+v, want %s %s", violations, tc.key, tc.detail)
			}
			wantPosture(t, eff, "pack=strict profile=strict yolo=false mode=copy import=false host_port_access=false")
		})
	}

	// Under a required pack --pack never applies; the required-pack
	// violation is the only one.
	eff, violations := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Admin.RequiredPack, o.Admin.Locked = "strict", []string{"yolo"}
	}), Flags{Pack: "open"})
	wantViolations(t, violations, Violation{Constraint: requiredPackConstraint})
	wantPosture(t, eff, "pack=strict yolo=false")
}

func packMasks(t *testing.T, name string) []string {
	t.Helper()
	pack, err := Builtin(name)
	if err != nil {
		t.Fatal(err)
	}
	return pack.Workspace.Masks
}

// TestResolveRunsTheComparedPack: the --pack that the locked check compared
// with the configured pack is the one that runs, even when the file changes
// between the check and the run.
func TestResolveRunsTheComparedPack(t *testing.T) {
	builtinBytes := func(name string) string {
		t.Helper()
		data, err := fs.ReadFile(sandboxpolicies.BuiltinPacks(), path.Join(name, PackFileName))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Replace(string(data), "name: "+name, "name: mine", 1)
	}
	root := t.TempDir()
	file := filepath.Join(writePack(t, root, "mine", builtinBytes("strict")), PackFileName)
	loose := builtinBytes("open")

	// Each LoadFile checks the pack directory's owner before it reads the
	// file; the second check of "mine" swaps in the loose content.
	checks := 0
	fakeOwners(t, func(info fs.FileInfo) int {
		if info.IsDir() && info.Name() == "mine" {
			if checks++; checks == 2 {
				if err := os.WriteFile(file, []byte(loose), 0o644); err != nil {
					t.Error(err)
				}
			}
		}
		return testUID
	})
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.PackDir, o.Admin.Locked = "strict", root, []string{"pack"}
	})
	eff, violations := mustResolve(t, cfg, Flags{Pack: "mine"})
	wantViolations(t, violations)
	wantPosture(t, eff, "pack=mine profile=strict yolo=false mode=copy")
	if checks != 1 {
		t.Fatalf("the --pack was read %d times, want once", checks)
	}
}

func TestResolveReviewFloor(t *testing.T) {
	for _, glob := range reviewFloor {
		if err := config.ValidateOpenShellProjectGlob(glob); err != nil {
			t.Errorf("review floor %q: %v", glob, err)
		}
	}
	// A custom pack without review globs still gets the floor, and a
	// built-in pack keeps its own globs.
	root := teamPackDir(t)
	for _, cfg := range []*config.Config{
		testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "team", root }),
		testConfig(nil),
	} {
		eff, _ := mustResolve(t, cfg, Flags{})
		for _, glob := range []string{"**/.claude/**", ".mcp.json", "**/.codex/**", "AGENTS.md", "CLAUDE.md", "**/.cursor/**",
			"**/.devin/**", "**/.openhands/**", "**/.omnigent/**", ".github/hooks/**", ".github/copilot/**",
			"package-lock.json", "yarn.lock", "go.sum", "Cargo.lock", "uv.lock", PackFileName, RepoPolicyPath} {
			if !containsString(eff.Workspace.Review, glob) {
				t.Fatalf("pack %s review %v lacks %q", eff.Pack.Name, eff.Workspace.Review, glob)
			}
		}
		if eff.Pack.Builtin && !containsString(eff.Workspace.Review, "package.json") {
			t.Fatalf("the built-in pack's own review globs were dropped: %v", eff.Workspace.Review)
		}
		wantSetting(t, eff, "workdir.review", listValue(eff.Workspace.Review), SourcePack,
			"pack "+eff.Pack.Name+" + defenseclaw review floor")
	}
}

func TestResolvePolicySources(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	root := filepath.Join(home, "packs")
	teamDir := writePack(t, root, "team", customPack("team"))
	other := writePack(t, t.TempDir(), "other", customPack("other"))

	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Pack, o.PackDir = "team", "~/packs" }),
		Flags{Pack: other})
	want := []string{filepath.Join(other, PackFileName), root, filepath.Join(teamDir, PackFileName)}
	sort.Strings(want)
	if got := eff.PolicySources(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PolicySources() = %v, want %v", got, want)
	}
	// Built-in packs are embedded: only the pack directory is a source.
	eff, _ = mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.PackDir = root }), Flags{Pack: "strict"})
	if got := eff.PolicySources(); !reflect.DeepEqual(got, []string{root}) {
		t.Fatalf("PolicySources() = %v", got)
	}
}

func TestResolveReservesPrometheusListeners(t *testing.T) {
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "metrics", Kind: config.ObservabilityV8DestinationPrometheus, Listen: "127.0.0.1:9464", Path: "/metrics"},
			{Name: "all-interfaces", Kind: config.ObservabilityV8DestinationPrometheus, Listen: ":9465", Path: "/metrics"},
			{Name: "off", Kind: config.ObservabilityV8DestinationPrometheus, Listen: "127.0.0.1:9466", Path: "/metrics",
				Enabled: boolPtr(false)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	eff, violations := mustResolve(t, testConfig(nil), Flags{HostPorts: []int{9464, 9465, 9466}, Observability: plan})
	wantViolations(t, violations, Violation{Constraint: "defenseclaw"}, Violation{Constraint: "defenseclaw"})
	wantPosture(t, eff, "host_ports=9466")
	for _, v := range violations {
		if !strings.Contains(v.Message, "Prometheus exporter") {
			t.Fatalf("violation %+v", v)
		}
	}
	if err := eff.Allow(Action{Kind: ActionApprove, Host: OpenShellHostAlias, Port: 9464}); err == nil {
		t.Fatal("approving the Prometheus listener was allowed")
	}
	// Without the plan nothing is known about the listeners.
	eff, violations = mustResolve(t, testConfig(nil), Flags{HostPorts: []int{9464}})
	wantViolations(t, violations)
	wantPosture(t, eff, "host_ports=9464")
}
