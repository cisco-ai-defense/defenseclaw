// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0535: with this package linked, the sandbox advisories judge a
// required_for connector by its standalone route: Antigravity's hooks are
// per user, so its host runs are not refused; Claude Code's are machine
// policy.
func TestSandboxAdvisoriesUseTheStandaloneRoute(t *testing.T) {
	cfg := &config.Config{}
	cfg.OpenShell.Admin = config.OpenShellAdminConfig{RequiredFor: []string{"antigravity", "claudecode"}, RequestAccess: "it@example.invalid"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		got := strings.Join(cfg.SandboxAdvisories(goos), "\n")
		if !strings.Contains(got, "required_for names antigravity (openshell.admin), which has no machine-owned hook on "+goos) {
			t.Errorf("%s: antigravity is not named:\n%s", goos, got)
		}
		if strings.Contains(got, "names claudecode") {
			t.Errorf("%s: claudecode is named:\n%s", goos, got)
		}
	}
}
