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

package sandboxcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// An organization's refusal names the key, the reason, the constraint and
// the way on (manual test M9: "blocked by your organization's DefenseClaw
// policy: harness" and nothing else). The violations are the ones package
// packs produces for each openshell.admin constraint.
func TestAdminRefusalsSayWhy(t *testing.T) {
	on, off := true, false
	home := t.TempDir()
	project := filepath.Join(home, "work", "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		admin  config.OpenShellAdminConfig
		action packs.Action
		want   string
	}{
		{"allowed_harnesses", config.OpenShellAdminConfig{AllowedHarnesses: []string{"claudecode"}}, packs.Action{Kind: packs.ActionHarness, Harness: "codex"},
			"blocked by your organization's DefenseClaw policy: harness — your organization allows only claude (openshell.admin.allowed_harnesses); ask your administrator if you need it"},
		{"allow_unblock", config.OpenShellAdminConfig{AllowUnblock: &off}, packs.Action{Kind: packs.ActionUnblock, Host: "example.org"},
			"blocked by your organization's DefenseClaw policy: egress.unblock — blocked destinations cannot be unblocked; ask your administrator (openshell.admin.allow_unblock)"},
		{"egress_block", config.OpenShellAdminConfig{EgressBlock: []string{"*.example.net"}}, packs.Action{Kind: packs.ActionUnblock, Host: "www.example.net"},
			"blocked by your organization's DefenseClaw policy: egress.unblock — www.example.net matches *.example.net on your organization's blocklist (openshell.admin.egress_block); ask your administrator if you need it"},
		{"egress_allow_only", config.OpenShellAdminConfig{EgressAllowOnly: []string{"*.github.com"}}, packs.Action{Kind: packs.ActionUnblock, Host: "example.org"},
			"— example.org is not on your organization's list of allowed destinations (openshell.admin.egress_allow_only); ask your administrator if you need it"},
		{"allow_mount", config.OpenShellAdminConfig{AllowMount: &off}, packs.Action{Kind: packs.ActionMount, Path: project},
			"workdir.mode — live host mounts are disabled; use copy mode (openshell.admin.allow_mount); run it with --copy (a sandbox that mounts the folder live must be deleted and run again with --copy)"},
		{"require_copy_for", config.OpenShellAdminConfig{AllowMount: &on, RequireCopyFor: []string{project}}, packs.Action{Kind: packs.ActionMount, Path: project},
			"your organization requires copy mode for projects matching " + project + " (openshell.admin.require_copy_for); run it with --copy"},
		{"allow_host_ports", config.OpenShellAdminConfig{AllowHostPorts: &off}, packs.Action{Kind: packs.ActionHostPort, Port: 3000},
			"mcp.host_ports — host ports cannot be opened to sandboxes (openshell.admin.allow_host_ports); run it without --host-port"},
		{"allow_yolo", config.OpenShellAdminConfig{AllowYolo: &off}, packs.Action{Kind: packs.ActionYolo},
			"yolo — skip-permissions mode is disabled; the harness keeps its permission prompts (openshell.admin.allow_yolo)"},
		{"allow_learn_mode", config.OpenShellAdminConfig{AllowLearnMode: &off}, packs.Action{Kind: packs.ActionLearnMode},
			"learn — learn mode is disabled (openshell.admin.allow_learn_mode)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{DataDir: t.TempDir()}
			cfg.OpenShell.Enabled = true
			cfg.OpenShell.Admin = c.admin
			eff, _, err := packs.Resolve(cfg, packs.Flags{Harness: "claudecode", Project: project})
			if err != nil {
				t.Fatal(err)
			}
			err = eff.Allow(c.action)
			var v *packs.Violation
			if !errors.As(err, &v) {
				t.Fatalf("Allow = %v", err)
			}
			w := wireViolation(*v)
			// The daemon's API error carries the same violation.
			got := apiError(&sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: v.Message, Detail: v.Detail, Violation: &w}).Error()
			if !strings.Contains(got, c.want) || !strings.HasPrefix(got, sandboxapi.AdminMessage+": ") {
				t.Fatalf("message:\n%s\nwant it to contain:\n%s", got, c.want)
			}
		})
	}
}

// `policy allow` refuses a host the organization's policy keeps closed,
// whatever the entry says (manual test M10: "✓ added" for a host the
// organization blocks), and names the bare-domain blocklist entries that
// leave subdomains open.
func TestPolicyAllowRespectsTheOrganization(t *testing.T) {
	off := false
	for _, c := range []struct {
		name  string
		admin config.OpenShellAdminConfig
		host  string
		want  string
	}{
		{"egress_block", config.OpenShellAdminConfig{EgressBlock: []string{"example.net"}}, "example.net",
			"blocked by your organization's DefenseClaw policy: egress.allow — example.net is on your organization's blocklist (example.net) (openshell.admin.egress_block)"},
		{"egress_block wildcard", config.OpenShellAdminConfig{EgressBlock: []string{"*.example.net"}}, "*.api.example.net", "openshell.admin.egress_block"},
		{"egress_allow_only", config.OpenShellAdminConfig{EgressAllowOnly: []string{"*.github.com"}}, "example.com",
			"example.com is not on your organization's list of allowed destinations (openshell.admin.egress_allow_only)"},
		{"allow_unblock", config.OpenShellAdminConfig{AllowUnblock: &off}, "example.com",
			"your own allow entries are ignored; ask your administrator to add destinations (openshell.admin.allow_unblock)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			writeConfig(t, ta, "")
			ta.Cfg.OpenShell.Admin = c.admin
			before, _ := os.ReadFile(ta.ConfigPath)
			err := ta.PolicyEdit(context.Background(), "allow", []string{c.host})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("PolicyEdit = %v, want %q", err, c.want)
			}
			if after, _ := os.ReadFile(ta.ConfigPath); string(after) != string(before) {
				t.Fatal("a refused entry was written")
			}
		})
	}
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.Cfg.OpenShell.Admin = config.OpenShellAdminConfig{EgressAllowOnly: []string{"*.github.com"}, EgressBlock: []string{"example.net", "*.example.org", "example.org"}}
	if err := ta.PolicyEdit(context.Background(), "allow", []string{"api.github.com"}); err != nil {
		t.Fatalf("an entry inside the allow-only list: %v", err)
	}
	warnings := ta.adminWarnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "openshell.admin.egress_block example.net blocks example.net itself, not its subdomains") ||
		!strings.Contains(warnings[0], "add *.example.net") {
		t.Fatalf("warnings = %q", warnings)
	}
	if c := ta.adminCheck(); c.Status != openshell.StatusWarn || !strings.Contains(c.Detail, "add *.example.net") {
		t.Fatalf("doctor check = %+v", c)
	}
}

// `policy show` sizes its key column to the longest key; `policy explain`
// cuts long values, lists every organization constraint, and allow entries
// outside the allow-only list as unreachable (manual test L7).
func TestPolicyOutputFormatting(t *testing.T) {
	on, off := true, false
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Admin = config.OpenShellAdminConfig{RequiredPack: "strict", AllowYolo: &off, AllowMount: &on,
		RequireCopyFor: []string{"~/clients/*"}, EgressAllowOnly: []string{"*.github.com"}}
	var masks []string
	for i := 0; i < 24; i++ {
		masks = append(masks, "**/secret-"+strings.Repeat("x", 30)+string(rune('a'+i))+"/*")
	}
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
		sandboxapi.Setting{Key: "hooks.fail_mode", Value: "closed", Source: "pack", Origin: "pack strict"},
		sandboxapi.Setting{Key: "egress.admin_block", Value: "example.net", Source: "admin", Origin: "openshell.admin.egress_block"},
		sandboxapi.Setting{Key: "egress.allow_only", Value: "*.github.com", Source: "admin", Origin: "openshell.admin.egress_allow_only"},
		sandboxapi.Setting{Key: "egress.allow", Value: "api.github.com, registry.npmjs.org", Source: "user", Origin: "openshell.egress.allow"},
		sandboxapi.Setting{Key: "workdir.masks", Value: strings.Join(masks, ", "), Source: "pack", Origin: "pack strict"},
	)
	if err := ta.PolicyShow(context.Background(), PolicyOptions{}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	for _, want := range []string{"hooks.fail_mode     closed", "egress.admin_block  example.net",
		"egress.allow        api.github.com (1 entry outside the organization's allow-only list: not reachable)"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	ta.out.Reset()
	if err := ta.PolicyExplain(context.Background(), PolicyOptions{}); err != nil {
		t.Fatal(err)
	}
	out = ta.output()
	// Every line of the table and the constraints fits 120 columns; only
	// the warnings, which are sentences, may wrap.
	for _, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > 120 && !strings.HasPrefix(line, "  ⚠") {
			t.Fatalf("explain line of %d characters:\n%s", n, line)
		}
	}
	for _, want := range []string{"more; -o json lists all)", "Organization constraints (openshell.admin)", "required_pack          strict",
		"allow_yolo             false", "require_copy_for       ~/clients/*", "egress_allow_only      *.github.com",
		"egress.allow: 1 entry outside the organization's allow-only list: not reachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain lacks %q:\n%s", want, out)
		}
	}
}

// `pack list` shows an invalid pack's whole error below the table, not cut
// with "…" (manual test L10).
func TestPackListShowsTheWholeError(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.PackDir = filepath.Join(ta.Cfg.DataDir, "packs")
	key := "a_key_no_pack_format_has_ever_had_" + strings.Repeat("x", 60)
	if err := os.MkdirAll(filepath.Join(ta.Cfg.OpenShell.PackDir, "broken"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ta.Cfg.OpenShell.PackDir, "broken", "pack.yaml"), []byte("version: 1\nname: broken\n"+key+": 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ta.PackList(PackOptions{}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	if !strings.Contains(out, "invalid (see below)") || !strings.Contains(out, "✗ broken: ") || !strings.Contains(out, key) || strings.Contains(out, "…") {
		t.Fatalf("pack list:\n%s", out)
	}
}
