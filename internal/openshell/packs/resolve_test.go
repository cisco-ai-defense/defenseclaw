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

package packs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

func TestResolveDefaults(t *testing.T) {
	eff, violations := mustResolve(t, testConfig(nil), Flags{})
	if len(violations) != 0 {
		t.Fatalf("violations = %+v", violations)
	}
	if eff.Pack.Name != "open" || eff.Profile != "open" || eff.NetworkMode != NetworkOpen || eff.Approvals != ApprovalsTriage {
		t.Fatalf("posture = pack %s profile %s network %s approvals %s", eff.Pack.Name, eff.Profile, eff.NetworkMode, eff.Approvals)
	}
	if !eff.Yolo || eff.Workspace.Mode != "mount" || !eff.MCP.Import || !eff.MCP.HostPortAccess || eff.Learn {
		t.Fatalf("switches = %+v", eff)
	}
	if eff.HookFailMode != FailModeClosed || eff.Harness != "" || eff.AllowedHarnesses != nil {
		t.Fatalf("hooks %q harness %q allowed %v", eff.HookFailMode, eff.Harness, eff.AllowedHarnesses)
	}
	if !reflect.DeepEqual(eff.Egress.Feeds, []string{FeedBuiltin}) || !reflect.DeepEqual(eff.Egress.Ports, []int{80, 443}) ||
		eff.Egress.LargeUploadMB != 25 || len(eff.Egress.Block) != 0 || len(eff.Egress.AdminBlock) != 0 {
		t.Fatalf("egress = %+v", eff.Egress)
	}
	if eff.Workspace.MaxUploadMB != 500 || eff.Workspace.GitDepth != 200 || eff.Workspace.OnExit != "ask" ||
		len(eff.Workspace.Unmask) != 0 || !containsString(eff.Workspace.Masks, ".env") {
		t.Fatalf("workspace = %+v", eff.Workspace)
	}
	if eff.Resources != (Resources{}) || len(eff.MCP.HostPorts) != 0 {
		t.Fatalf("resources %+v host ports %v", eff.Resources, eff.MCP.HostPorts)
	}
	if eff.Admin.Configured || eff.Admin.Authority != AuthorityAdvisory {
		t.Fatalf("admin status = %+v", eff.Admin)
	}
	wantSetting(t, eff, "pack", "open", SourceDefault, "default pack")
	wantSetting(t, eff, "profile", "open", SourcePack, "pack open")
	wantSetting(t, eff, "yolo", "true", SourcePack, "pack open")
	wantSetting(t, eff, "workdir.unmask", "(none)", SourceDefault, "")
	wantSetting(t, eff, "workdir.git_depth", "200", SourceDefault, "")
	wantSetting(t, eff, "mcp.host_ports", "(none)", SourceDefault, "")
	wantSetting(t, eff, "resources.cpu", "(unlimited)", SourceDefault, "")
	wantSetting(t, eff, "learn", "false", SourceDefault, "")
	wantSetting(t, eff, "hooks.fail_mode", "closed", SourcePack, "pack open")

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
		{"unmask by user", func(o *config.OpenShellConfig) { o.Workdir.Unmask = []string{".env.example"} }, Flags{}, "workdir.unmask", ".env.example", SourceUser, "openshell.workdir.unmask"},
		{"unmask merge flag", func(o *config.OpenShellConfig) { o.Workdir.Unmask = []string{".env.example"} }, Flags{Unmask: []string{"certs/dev.pem", ".env.example"}}, "workdir.unmask", ".env.example, certs/dev.pem", SourceFlag, "--unmask"},
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
	if eff.Harness != "codex" || eff.Resources != (Resources{CPU: "1", Memory: "2Gi"}) {
		t.Fatalf("harness %q resources %+v", eff.Harness, eff.Resources)
	}

	balanced, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Pack = "balanced" }), Flags{})
	if balanced.NetworkMode != NetworkAllowlist || !containsString(balanced.Egress.Allow, "registry.npmjs.org") ||
		balanced.Egress.LargeUploadMB != 10 {
		t.Fatalf("balanced pack = %+v", balanced.Egress)
	}
	strict, _ := mustResolve(t, testConfig(nil), Flags{Pack: "strict"})
	if strict.NetworkMode != NetworkDeny || strict.Workspace.Mode != "copy" || strict.Yolo || strict.MCP.Import ||
		strict.MCP.HostPortAccess || strict.Approvals != ApprovalsManual {
		t.Fatalf("strict pack = %+v", strict)
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

func TestResolveAdminClamps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		user  func(*config.OpenShellConfig)
		flags Flags
		check func(t *testing.T, eff *Effective, violations []Violation)
	}{
		{"min profile clamps the user", func(o *config.OpenShellConfig) {
			o.Profile, o.Admin.MinProfile = "open", "balanced"
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Key != "profile" || v.Source != SourceUser || v.Attempted != "open" || v.Enforced != "balanced" ||
				v.Constraint != "openshell.admin.min_profile" || !v.Admin() || v.Fatal {
				t.Fatalf("violation = %+v", v)
			}
			if v.Message != "blocked by your organization's DefenseClaw policy: profile" ||
				!strings.Contains(v.Error(), "at least the balanced profile") {
				t.Fatalf("message = %q", v.Error())
			}
			if eff.Profile != "balanced" || eff.NetworkMode != NetworkAllowlist || eff.Approvals != ApprovalsTriage {
				t.Fatalf("effective = %s %s %s", eff.Profile, eff.NetworkMode, eff.Approvals)
			}
			got, _ := eff.Setting("profile")
			if got.Source != SourceAdmin || got.Requested != "open" || got.Origin != "openshell.admin.min_profile" {
				t.Fatalf("profile setting = %+v", got)
			}
			wantSetting(t, eff, "network.mode", NetworkAllowlist, SourceAdmin, "profile balanced")
		}},
		{"min profile clamps a flag", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "strict" },
			Flags{Profile: "balanced"}, func(t *testing.T, eff *Effective, violations []Violation) {
				v := onlyViolation(t, violations)
				if v.Source != SourceFlag || v.Enforced != "strict" || eff.Profile != "strict" || eff.Approvals != ApprovalsManual {
					t.Fatalf("violation %+v effective %s/%s", v, eff.Profile, eff.Approvals)
				}
			}},
		{"min profile silently raises the default pack", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" },
			Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
				if len(violations) != 0 || eff.Profile != "balanced" {
					t.Fatalf("violations %+v profile %s", violations, eff.Profile)
				}
				got, _ := eff.Setting("profile")
				if got.Source != SourceAdmin || got.Requested != "open" {
					t.Fatalf("setting = %+v", got)
				}
			}},
		{"min profile keeps a stricter choice", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" },
			Flags{Profile: "strict"}, func(t *testing.T, eff *Effective, violations []Violation) {
				if len(violations) != 0 || eff.Profile != "strict" {
					t.Fatalf("violations %+v profile %s", violations, eff.Profile)
				}
			}},
		{"allow-only forces an allowlist profile", func(o *config.OpenShellConfig) {
			o.Profile, o.Admin.EgressAllowOnly = "open", []string{"*.Corp.Example"}
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Constraint != "openshell.admin.egress_allow_only" || eff.Profile != "balanced" ||
				!reflect.DeepEqual(eff.Egress.AllowOnly, []string{"*.corp.example"}) {
				t.Fatalf("violation %+v profile %s allow-only %v", v, eff.Profile, eff.Egress.AllowOnly)
			}
		}},
		{"min profile beats allow-only", func(o *config.OpenShellConfig) {
			o.Admin.EgressAllowOnly, o.Admin.MinProfile = []string{"corp.example"}, "strict"
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			if eff.Profile != "strict" {
				t.Fatalf("profile = %s", eff.Profile)
			}
			wantSetting(t, eff, "profile", "strict", SourceAdmin, "openshell.admin.min_profile")
		}},
		{"yolo off clamps the pack silently", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) },
			Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
				if len(violations) != 0 || eff.Yolo {
					t.Fatalf("violations %+v yolo %v", violations, eff.Yolo)
				}
				wantSetting(t, eff, "yolo", "false", SourceAdmin, "openshell.admin.allow_yolo")
			}},
		{"yolo off refuses the user", func(o *config.OpenShellConfig) {
			o.Yolo, o.Admin.AllowYolo = boolPtr(true), boolPtr(false)
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Key != "yolo" || v.Source != SourceUser || v.Enforced != "false" || eff.Yolo {
				t.Fatalf("violation %+v", v)
			}
		}},
		{"yolo off refuses a flag", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) },
			Flags{Yolo: true}, func(t *testing.T, eff *Effective, violations []Violation) {
				if v := onlyViolation(t, violations); v.Source != SourceFlag {
					t.Fatalf("violation %+v", v)
				}
			}},
		{"yolo off accepts --safe", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) },
			Flags{Safe: true}, func(t *testing.T, eff *Effective, violations []Violation) {
				if len(violations) != 0 || eff.Yolo {
					t.Fatalf("violations %+v", violations)
				}
			}},
		{"yolo off refuses a chosen pack's default", func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.AllowYolo = "open", boolPtr(false)
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			if v := onlyViolation(t, violations); v.Source != SourcePack || v.Key != "yolo" {
				t.Fatalf("violation %+v", v)
			}
		}},
		{"mounts off", func(o *config.OpenShellConfig) {
			o.Workdir.Mode, o.Admin.AllowMount = "mount", boolPtr(false)
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Key != "workdir.mode" || v.Constraint != "openshell.admin.allow_mount" || eff.Workspace.Mode != "copy" {
				t.Fatalf("violation %+v mode %s", v, eff.Workspace.Mode)
			}
		}},
		{"mounts off accepts --copy", func(o *config.OpenShellConfig) { o.Admin.AllowMount = boolPtr(false) },
			Flags{Copy: true}, func(t *testing.T, eff *Effective, violations []Violation) {
				if len(violations) != 0 || eff.Workspace.Mode != "copy" {
					t.Fatalf("violations %+v", violations)
				}
				wantSetting(t, eff, "workdir.mode", "copy", SourceFlag, "--copy")
			}},
		{"require copy for a project", func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.RequireCopyFor = "open", []string{"/src/customer-*"}
		}, Flags{Project: "/src/customer-acme/app"}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Constraint != "openshell.admin.require_copy_for" || v.Source != SourcePack || eff.Workspace.Mode != "copy" ||
				!strings.Contains(v.Detail, "/src/customer-*") {
				t.Fatalf("violation %+v mode %s", v, eff.Workspace.Mode)
			}
		}},
		{"require copy elsewhere", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-*"} },
			Flags{Project: "/src/internal/app"}, func(t *testing.T, eff *Effective, violations []Violation) {
				if len(violations) != 0 || eff.Workspace.Mode != "mount" {
					t.Fatalf("violations %+v mode %s", violations, eff.Workspace.Mode)
				}
			}},
		{"unblock off keeps the feed", func(o *config.OpenShellConfig) {
			o.Egress.Feed, o.Admin.AllowUnblock = "none", boolPtr(false)
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Key != "egress.feeds" || v.Enforced != FeedBuiltin || !reflect.DeepEqual(eff.Egress.Feeds, []string{FeedBuiltin}) {
				t.Fatalf("violation %+v feeds %v", v, eff.Egress.Feeds)
			}
		}},
		{"unblock off drops user allow entries", func(o *config.OpenShellConfig) {
			o.Pack, o.Egress.Allow, o.Admin.AllowUnblock = "balanced", []string{"paste.example"}, boolPtr(false)
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Key != "egress.allow" || v.Attempted != "paste.example" || containsString(eff.Egress.Allow, "paste.example") ||
				!containsString(eff.Egress.Allow, "pypi.org") {
				t.Fatalf("violation %+v allow %v", v, eff.Egress.Allow)
			}
			got, _ := eff.Setting("egress.allow")
			if got.Source != SourceAdmin || !strings.Contains(got.Requested, "paste.example") {
				t.Fatalf("setting %+v", got)
			}
		}},
		{"admin blocklist is merged", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"*.Ngrok.io", "*.ngrok.io"}
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			if len(violations) != 0 || !reflect.DeepEqual(eff.Egress.AdminBlock, []string{"*.ngrok.io"}) {
				t.Fatalf("admin block %v", eff.Egress.AdminBlock)
			}
			wantSetting(t, eff, "egress.admin_block", "*.ngrok.io", SourceAdmin, "")
		}},
		{"host ports off", func(o *config.OpenShellConfig) {
			o.MCP.HostPorts, o.Admin.AllowHostPorts = []int{5432}, boolPtr(false)
		}, Flags{HostPorts: []int{6379}}, func(t *testing.T, eff *Effective, violations []Violation) {
			if len(violations) != 2 || violations[0].Source != SourceUser || violations[1].Source != SourceFlag ||
				violations[0].Constraint != "openshell.admin.allow_host_ports" {
				t.Fatalf("violations %+v", violations)
			}
			if eff.MCP.HostPortAccess || len(eff.MCP.HostPorts) != 0 {
				t.Fatalf("mcp = %+v", eff.MCP)
			}
			wantSetting(t, eff, "mcp.host_port_access", "false", SourceAdmin, "")
			got, _ := eff.Setting("mcp.host_ports")
			if got.Value != "(none)" || got.Source != SourceAdmin || got.Requested != "5432, 6379" {
				t.Fatalf("setting %+v", got)
			}
		}},
		{"strict pack refuses host ports", func(o *config.OpenShellConfig) {
			o.Pack, o.MCP.HostPorts = "strict", []int{5432}
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Constraint != "pack strict" || v.Admin() || v.Message != "not allowed by the strict sandbox pack: mcp.host_ports" {
				t.Fatalf("violation %+v", v)
			}
			wantSetting(t, eff, "mcp.host_ports", "(none)", SourcePack, "pack strict")
		}},
		{"resource ceilings", func(o *config.OpenShellConfig) {
			o.Resources.CPU = "4"
			o.Admin.MaxResources = config.OpenShellResourcesConfig{CPU: "2", Memory: "8Gi"}
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Key != "resources.cpu" || v.Attempted != "4" || v.Enforced != "2" || !strings.Contains(v.Detail, "cpu at 2") {
				t.Fatalf("violation %+v", v)
			}
			if eff.Resources != (Resources{CPU: "2", Memory: "8Gi"}) {
				t.Fatalf("resources %+v", eff.Resources)
			}
			got, _ := eff.Setting("resources.memory")
			if got.Source != SourceAdmin || got.Requested != "(unlimited)" {
				t.Fatalf("memory setting %+v", got)
			}
		}},
		{"resource flag over the ceiling", func(o *config.OpenShellConfig) {
			o.Admin.MaxResources = config.OpenShellResourcesConfig{Memory: "8Gi"}
		}, Flags{Memory: "16G", CPU: "1500m"}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := onlyViolation(t, violations)
			if v.Source != SourceFlag || v.Key != "resources.memory" || eff.Resources != (Resources{CPU: "1500m", Memory: "8Gi"}) {
				t.Fatalf("violation %+v resources %+v", v, eff.Resources)
			}
		}},
		{"resource within the ceiling", func(o *config.OpenShellConfig) {
			o.Resources.Memory = "8G"
			o.Admin.MaxResources = config.OpenShellResourcesConfig{Memory: "8Gi"}
		}, Flags{}, func(t *testing.T, eff *Effective, violations []Violation) {
			if len(violations) != 0 || eff.Resources.Memory != "8G" {
				t.Fatalf("violations %+v resources %+v", violations, eff.Resources)
			}
		}},
		{"harness outside the admin list", func(o *config.OpenShellConfig) {
			o.Admin.AllowedHarnesses = []string{"claude-code"}
		}, Flags{Harness: "codex"}, func(t *testing.T, eff *Effective, violations []Violation) {
			v := FirstFatal(violations)
			if v == nil || v.Key != "harness" || v.Source != SourceFlag || v.Constraint != "openshell.admin.allowed_harnesses" {
				t.Fatalf("violations %+v", violations)
			}
			if eff.Harness != "" || !reflect.DeepEqual(eff.AllowedHarnesses, []string{"claudecode"}) {
				t.Fatalf("harness %q allowed %v", eff.Harness, eff.AllowedHarnesses)
			}
			wantSetting(t, eff, "harness", "(refused: codex)", SourceAdmin, "")
		}},
		{"harness on the admin list", func(o *config.OpenShellConfig) {
			o.Admin.AllowedHarnesses = []string{"claude-code", "codex"}
		}, Flags{Harness: "claude_code"}, func(t *testing.T, eff *Effective, violations []Violation) {
			if len(violations) != 0 || eff.Harness != "claudecode" || FirstFatal(violations) != nil {
				t.Fatalf("violations %+v harness %q", violations, eff.Harness)
			}
		}},
		{"learn mode off", func(o *config.OpenShellConfig) { o.Admin.AllowLearnMode = boolPtr(false) },
			Flags{Learn: true}, func(t *testing.T, eff *Effective, violations []Violation) {
				v := onlyViolation(t, violations)
				if v.Key != "learn" || v.Source != SourceFlag || eff.Learn {
					t.Fatalf("violation %+v learn %v", v, eff.Learn)
				}
				wantSetting(t, eff, "learn", "false", SourceAdmin, "openshell.admin.allow_learn_mode")
			}},
		{"permissive switches change nothing", func(o *config.OpenShellConfig) {
			o.Admin.AllowYolo, o.Admin.AllowMount, o.Admin.AllowHostPorts = boolPtr(true), boolPtr(true), boolPtr(true)
			o.Admin.AllowUnblock, o.Admin.AllowLearnMode = boolPtr(true), boolPtr(true)
			o.MCP.HostPorts = []int{5432}
		}, Flags{Learn: true}, func(t *testing.T, eff *Effective, violations []Violation) {
			if len(violations) != 0 || !eff.Yolo || eff.Workspace.Mode != "mount" || !eff.Learn ||
				!reflect.DeepEqual(eff.MCP.HostPorts, []int{5432}) {
				t.Fatalf("violations %+v effective %+v", violations, eff)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, violations := mustResolve(t, testConfig(tc.user), tc.flags)
			tc.check(t, eff, violations)
		})
	}
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
}

func TestResolveLockedFlags(t *testing.T) {
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.Profile, o.Yolo = "balanced", "balanced", boolPtr(true)
		o.Resources.CPU = "2"
		o.MCP.HostPorts = []int{5432}
		o.Admin.Locked = append([]string(nil), config.OpenShellLockableKeys...)
	})
	flags := Flags{
		Pack: "strict", Profile: "strict", Safe: true, Copy: true, Unmask: []string{".env"}, NoMCP: true,
		HostPorts: []int{6379}, CPU: "1", Memory: "1Gi", Harness: "codex", Learn: true,
	}
	eff, violations := mustResolve(t, cfg, flags)
	attempted := map[string]string{}
	for _, v := range violations {
		if v.Constraint != "openshell.admin.locked" || v.Source != SourceFlag ||
			v.Message != "blocked by your organization's DefenseClaw policy: "+v.Key {
			t.Fatalf("violation %+v", v)
		}
		attempted[v.Key] = v.Attempted
	}
	want := map[string]string{
		"pack": "--pack strict", "profile": "--profile strict", "yolo": "--safe", "workdir.mode": "--copy",
		"workdir.unmask": "--unmask .env", "mcp.import": "--no-mcp", "mcp.host_ports": "--host-port 6379",
		"resources": "--cpu 1 --memory 1Gi",
	}
	if !reflect.DeepEqual(attempted, want) {
		t.Fatalf("locked violations = %v, want %v", attempted, want)
	}
	if eff.Pack.Name != "balanced" || eff.Profile != "balanced" || !eff.Yolo || eff.Workspace.Mode != "mount" ||
		len(eff.Workspace.Unmask) != 0 || !eff.MCP.Import || !reflect.DeepEqual(eff.MCP.HostPorts, []int{5432}) ||
		eff.Resources != (Resources{CPU: "2"}) {
		t.Fatalf("locked values were overridden: %+v", eff)
	}
	// Unlockable inputs still apply.
	if eff.Harness != "codex" || !eff.Learn {
		t.Fatalf("harness %q learn %v", eff.Harness, eff.Learn)
	}

	// --yolo is reported as such; unlocked keys are untouched.
	cfg.OpenShell.Admin.Locked = []string{"yolo"}
	eff, violations = mustResolve(t, cfg, Flags{Yolo: true, Copy: true})
	if v := onlyViolation(t, violations); v.Attempted != "--yolo" {
		t.Fatalf("violation %+v", v)
	}
	if eff.Workspace.Mode != "copy" {
		t.Fatalf("unlocked --copy was dropped")
	}
}

func TestResolveRequiredPack(t *testing.T) {
	root := t.TempDir()
	corpDir := writePack(t, root, "corp", strings.Replace(customPack("corp"), "harness: {yolo: true}", "harness: {yolo: true, allowed: [codex]}", 1))

	cfg := testConfig(func(o *config.OpenShellConfig) { o.Pack, o.Admin.RequiredPack = "open", "strict" })
	eff, violations := mustResolve(t, cfg, Flags{})
	v := onlyViolation(t, violations)
	if v.Key != "pack" || v.Source != SourceUser || v.Attempted != "open" || v.Enforced != "strict" ||
		v.Constraint != "openshell.admin.required_pack" {
		t.Fatalf("violation %+v", v)
	}
	if eff.Pack.Name != "strict" || eff.Yolo || eff.Workspace.Mode != "copy" {
		t.Fatalf("effective %+v", eff)
	}
	got, _ := eff.Setting("pack")
	if got.Source != SourceAdmin || got.Requested != "open" {
		t.Fatalf("pack setting %+v", got)
	}

	_, violations = mustResolve(t, cfg, Flags{Pack: "balanced"})
	if v := onlyViolation(t, violations); v.Source != SourceFlag || v.Attempted != "balanced" {
		t.Fatalf("violation %+v", v)
	}
	cfg.OpenShell.Pack = "strict"
	if _, violations = mustResolve(t, cfg, Flags{}); len(violations) != 0 {
		t.Fatalf("choosing the required pack: %+v", violations)
	}

	// The same content under another reference is not a loosening, and a
	// required pack's own values are not the user's attempts.
	cfg = testConfig(func(o *config.OpenShellConfig) {
		o.PackDir, o.Pack, o.Admin.RequiredPack = root, "corp", corpDir
		o.Admin.AllowYolo = boolPtr(false)
	})
	eff, violations = mustResolve(t, cfg, Flags{Harness: "codex"})
	if len(violations) != 0 || eff.Pack.Name != "corp" || eff.Yolo {
		t.Fatalf("violations %+v effective %+v", violations, eff)
	}
	_, violations = mustResolve(t, cfg, Flags{Pack: "missing-pack"})
	if v := onlyViolation(t, violations); v.Key != "pack" || v.Attempted != "missing-pack" {
		t.Fatalf("violation %+v", v)
	}

	cfg.OpenShell.Admin.RequiredPack = "no-such-pack"
	if _, _, err := Resolve(cfg, Flags{}); err == nil || !strings.Contains(err.Error(), "openshell.admin.required_pack") {
		t.Fatalf("missing required pack: %v", err)
	}
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
	if _, ok := eff.Setting("nope"); ok {
		t.Fatal("unknown key reported a setting")
	}
	var nilEff *Effective
	if nilEff.Explain() != nil {
		t.Fatal("nil Effective must explain nothing")
	}
	if _, ok := nilEff.Setting("pack"); ok {
		t.Fatal("nil Effective must have no settings")
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
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
		port int
		what string
	}{
		{"api", nil, 18970, "DefenseClaw's API"},
		{"ingress", nil, 18971, "sandbox hook ingress"},
		{"egress", nil, 18972, "egress proxy"},
		{"openshell gateway", nil, OpenShellGatewayPort, "the OpenShell gateway"},
		{"guardrail proxy", nil, 4000, "guardrail proxy"},
		{"default api port", func(c *config.Config) { c.Gateway.APIPort = 0 }, 18970, "DefenseClaw's API"},
		{"custom ingress", func(c *config.Config) { c.OpenShell.IngressPort = 20001 }, 20001, "sandbox hook ingress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(nil)
			if tc.edit != nil {
				tc.edit(cfg)
			}
			eff, violations := mustResolve(t, cfg, Flags{HostPorts: []int{tc.port, 5432}})
			v := onlyViolation(t, violations)
			if v.Constraint != "defenseclaw" || v.Source != SourceFlag || !strings.Contains(v.Message, tc.what) ||
				!strings.HasPrefix(v.Message, "DefenseClaw never opens") {
				t.Fatalf("violation %+v", v)
			}
			if !reflect.DeepEqual(eff.MCP.HostPorts, []int{5432}) {
				t.Fatalf("host ports %v", eff.MCP.HostPorts)
			}
		})
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
		t.Fatal("an empty project must not match")
	}
}
