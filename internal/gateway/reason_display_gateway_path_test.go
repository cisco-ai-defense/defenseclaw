// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The administrator the user is told to ask runs the gateway by its absolute
// path: it is not on the PATH (cowork-1-0-8 GAP-0081).
func TestProjectSkillPendingHintNamesTheManagedGatewayByItsFullPath(t *testing.T) {
	previousGOOS, previousStandalone := reasonDisplayGOOS, standaloneEnterpriseActive.Load()
	t.Cleanup(func() {
		reasonDisplayGOOS = previousGOOS
		standaloneEnterpriseActive.Store(previousStandalone)
	})
	standaloneEnterpriseActive.Store(true)
	const reason = "ASSET-POLICY reason_code=project-skill-pending source=project asset_type=skill asset_name=demo"
	for goos, gateway := range map[string]string{
		"linux":  "/opt/defenseclaw/bin/defenseclaw-gateway",
		"darwin": "/opt/cisco/defenseclaw/bin/defenseclaw-gateway",
	} {
		reasonDisplayGOOS = goos
		got := agentProjectSkillPendingSentence(reason)
		if !strings.Contains(got, "run `"+gateway+" scan skill PATH`") || strings.Contains(got, "`defenseclaw-gateway") {
			t.Errorf("%s: %q", goos, got)
		}
	}
}

// Secure Client does not run the standalone notice: the flag follows the
// profile, so its text is the one of release 1.0.5 on every OS (review round
// 4, S1).
func TestProjectSkillPendingHintOnSecureClientKeepsTheReleasedText(t *testing.T) {
	previousGOOS, previousStandalone := reasonDisplayGOOS, standaloneEnterpriseActive.Load()
	t.Cleanup(func() {
		reasonDisplayGOOS = previousGOOS
		standaloneEnterpriseActive.Store(previousStandalone)
	})
	const reason = "ASSET-POLICY reason_code=project-skill-pending source=project asset_type=skill asset_name=demo"
	const released = "DefenseClaw has not scanned project skill demo yet, so it is blocked. " +
		"Run `defenseclaw skill scan --path PATH` for its folder; then retry the skill."
	explicit := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	explicit.Enterprise.Profile = managed.ProfileSecureClient
	implicit := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	for name, cfg := range map[string]*config.Config{"explicit": explicit, "default": implicit} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			reasonDisplayGOOS = goos
			setStandaloneEnterpriseActive(cfg.StandaloneEnterprise())
			if got := agentProjectSkillPendingSentence(reason); got != released {
				t.Errorf("%s %s: %q, want %q", name, goos, got, released)
			}
		}
	}
}
