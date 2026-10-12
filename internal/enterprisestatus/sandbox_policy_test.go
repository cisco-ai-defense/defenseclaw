// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0536: the shared builder adds the default_profile warnings, then the
// advisories, as warnings only, the same list on a rerun.
func TestAddSandboxPolicyWarnings(t *testing.T) {
	f := false
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors":   {Mode: "action", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode", "codex"}, UserApprovals: "session"}},
		"offline-floor": {Mode: "action", Sandbox: &config.OpenShellAdminConfig{AllowMount: &f}},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{`CORP\Contractors`}}}}
	cfg.Guardrail.DefaultProfile = "offline-floor"
	render := func() string {
		r := &Result{}
		r.AddSandboxPolicyWarnings(cfg, "windows")
		if len(r.Errors) != 0 {
			t.Fatalf("errors = %+v", r.Errors)
		}
		var lines []string
		for _, w := range r.Warnings {
			lines = append(lines, w.Code+": "+w.Message)
		}
		return strings.Join(lines, "\n")
	}
	got := render()
	first := strings.Index(got, CodeSandboxDefaultProfile+": default_profile lacks required_for [claudecode, codex] from contractors")
	approvals := strings.Index(got, CodeSandboxDefaultProfile+": default_profile lacks user_approvals session from contractors")
	advisory := strings.Index(got, CodeSandboxAdvisory+": openshell.admin.request_access is empty")
	if first < 0 || approvals < 0 || advisory < first || advisory < approvals {
		t.Fatalf("warnings out of order or missing:\n%s", got)
	}
	if again := render(); again != got {
		t.Fatalf("a rerun differs:\n%s\n---\n%s", got, again)
	}
	var nilResult *Result
	nilResult.AddSandboxPolicyWarnings(cfg, "linux")
}
