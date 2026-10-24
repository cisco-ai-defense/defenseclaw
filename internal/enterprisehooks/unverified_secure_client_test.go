// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A standalone managed host whose process carries the Secure Client profile
// (not pinned standalone) but that is no authenticated Secure Client deployment
// (connector.SecureClientDeploymentVerified false) gets no Secure Client
// default: an unset mode does not open (main-sync review finding 5), and
// the standalone config resolves each connector to the administrator's
// value, closed when unset and open only when set (owner decision
// 2026-10-20).
func TestStandaloneHostWithSecureClientProcessProfileStaysClosed(t *testing.T) {
	useSecureClientHookDelivery(t)
	saved := connector.SecureClientDeploymentVerified
	connector.SecureClientDeploymentVerified = func() bool { return false }
	t.Cleanup(func() { connector.SecureClientDeploymentVerified = saved })
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if secureClientHookDelivery() {
		t.Fatal("an unverified install selected Secure Client delivery")
	}
	if got := canonicalHookFailMode(""); got != "closed" {
		t.Fatalf("unset fail mode on an unverified host = %q, want closed", got)
	}
	if got := canonicalHookFailModeFor("", true); got != "closed" {
		t.Fatalf("unset fail mode for an explicit Secure Client profile on an unverified host = %q, want closed", got)
	}
	if got := canonicalHookFailMode("open"); got != "open" {
		t.Fatalf("an explicit open = %q, want open", got)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	for _, configured := range []string{"", "open"} {
		cfg.Guardrail.HookFailMode = configured
		want := "closed"
		if configured == "open" {
			want = "open"
		}
		for _, name := range []string{"amp", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode"} {
			if got := cfg.EffectiveHookFailModeForConnector(name); got != want {
				t.Errorf("%s: standalone config with %q resolves %q, want %q", name, configured, got, want)
			}
			if got := ManagedHookFailMode(cfg, name); got != want {
				t.Errorf("%s: standalone ManagedHookFailMode with %q = %q, want %q", name, configured, got, want)
			}
		}
	}
}
