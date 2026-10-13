// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0386: status warns about a custom rule pack that every standard user
// can read, with the fix that leaves read to the gateway service account.
func TestWindowsEnterpriseRulePackReadableByUsersWarns(t *testing.T) {
	previous := windowsEnterpriseStandaloneRulePackReaders
	t.Cleanup(func() { windowsEnterpriseStandaloneRulePackReaders = previous })
	pack := filepath.Join(t.TempDir(), "es-strict")
	if err := os.Mkdir(pack, 0o700); err != nil {
		t.Fatal(err)
	}
	readable := true
	windowsEnterpriseStandaloneRulePackReaders = func(dir string) ([]string, error) {
		if readable && strings.EqualFold(dir, pack) {
			return []string{"S-1-5-32-545"}, nil
		}
		return nil, nil
	}
	cfg := &config.Config{}
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"es-strict": {Path: pack}}
	problems := windowsEnterpriseRulePackPrivacyProblems(cfg)
	if len(problems) != 1 || !strings.Contains(problems[0], pack) ||
		!strings.Contains(problems[0], `"`+managed.RulePackServiceReadGrant("")+`"`) ||
		!strings.Contains(problems[0], `/remove:g "*S-1-5-32-545" /T /C`) {
		t.Fatalf("problems %q, want one that names the pack and the gateway-only fix", problems)
	}
	readable = false
	if problems := windowsEnterpriseRulePackPrivacyProblems(cfg); len(problems) != 0 {
		t.Fatalf("problems %q for a pack only the gateway reads", problems)
	}
}

// GAP-0536: Setup /ensure, status and verify on Windows add the sandbox
// policy warnings Linux and macOS add, after the rule pack notes, as
// warnings only, the same list on a rerun.
func TestWindowsEnterpriseInstalledConfigWarnsAboutSandboxPolicy(t *testing.T) {
	previous := windowsEnterpriseStandaloneRulePackReaders
	t.Cleanup(func() { windowsEnterpriseStandaloneRulePackReaders = previous })
	windowsEnterpriseStandaloneRulePackReaders = func(string) ([]string, error) { return []string{"S-1-5-32-545"}, nil }
	pack := t.TempDir()
	f := false
	cfg := &config.Config{}
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"es-strict": {Path: pack}}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors":    {Mode: "action", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode", "codex"}}},
		"sandbox-admins": {Mode: "action", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"antigravity"}}},
		"offline-floor":  {Mode: "action", Sandbox: &config.OpenShellAdminConfig{AllowMount: &f}},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{`CORP\Contractors`}}},
		{Profile: "sandbox-admins", Match: config.ProfileMatch{Groups: []string{`CORP\Admins`}}},
	}
	cfg.Guardrail.DefaultProfile = "offline-floor"
	render := func() []enterprisestatus.Message {
		result := &enterprisestatus.Result{}
		addWindowsEnterpriseInstalledConfigWarnings(result, cfg)
		if len(result.Errors) != 0 {
			t.Fatalf("errors = %+v", result.Errors)
		}
		return result.Warnings
	}
	got := render()
	var codes, text []string
	for _, w := range got {
		codes = append(codes, w.Code)
		text = append(text, w.Message)
	}
	joined := strings.Join(text, "\n")
	for _, want := range []string{
		"default_profile lacks required_for [claudecode, codex] from contractors",
		"default_profile lacks required_for [antigravity] from sandbox-admins",
		"required_for names antigravity (sandbox-admins), which has no machine-owned hook on windows",
		"openshell.admin.request_access is empty",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if len(codes) == 0 || codes[0] != "rule_pack_readable_by_users" || codes[len(codes)-1] != enterprisestatus.CodeSandboxAdvisory {
		t.Errorf("codes out of order: %q", codes)
	}
	if again := render(); !reflect.DeepEqual(again, got) {
		t.Errorf("a rerun differs:\n%+v\n---\n%+v", got, again)
	}
}
