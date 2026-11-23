// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1733 review: the foreign-hook guard leaves the vendor hook configs of an
// account skipped for a per-user DefenseClaw install as found. That covers one
// whose rows carry the skip, and one without rows that the enumerator skipped.
// Neither is listed for cleanup, block reports or the Claude Code migration.
// An enrolled account with the same entry (tamper) and an account without one
// are still cleaned.
func TestGAP1733ForeignHookGuardLeavesPerUserInstallAccountsAsFound(t *testing.T) {
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousCleanup, previousBlocks := enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks
	previousRemover, previousProbe := windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe
	previousFolder, previousCfg := enterpriseHookPerUserInstallFolder, cfg
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks = previousCleanup, previousBlocks
		windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe = previousRemover, previousProbe
		enterpriseHookPerUserInstallFolder, cfg = previousFolder, previousCfg
		enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	scope := t.TempDir()
	// No protection ledger: every account without rows was never protected.
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	cfg = &config.Config{DataDir: filepath.Join(scope, "runtime"), DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"cursor"}, true, nil
	}
	const skipped, unlisted, tampered, plain = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1003", "S-1-5-21-1-2-3-1004"
	home := func(sid string) string { return `C:\Users\u` + sid[len(sid)-4:] }
	var profiles []enterprisehooks.TargetCredentials
	for _, sid := range []string{skipped, unlisted, tampered, plain} {
		profiles = append(profiles, enterprisehooks.TargetCredentials{UserHome: home(sid), UID: -1, GID: -1, SID: sid})
	}
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return profiles, nil
	}
	enterpriseHookPerUserInstallFolder = func(_, sid string) bool { return sid != plain }
	var cleaned, collected, probed []string
	enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, _, _ string) (enterprisepolicy.CleanupResult, error) {
		cleaned = append(cleaned, target.SID)
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseForeignHookCollectBlocks = func(target enterprisehooks.TargetCredentials) ([]enterprisepolicy.BlockSummary, int, error) {
		collected = append(collected, target.SID)
		return nil, 0, nil
	}
	windowsManagedClaudeRegistrationProbe = func(_, sid string) (bool, []string, error) {
		probed = append(probed, sid)
		return false, nil, nil
	}
	windowsManagedClaudeSettingsRemover = func(string, string) (int, []string, error) { return 0, nil, nil }
	rows := []enterpriseHookReconcileRow{
		{SID: skipped, UserHome: home(skipped), Connector: "codex", Error: enterpriseHookAccountPerUserInstallFailure},
		{SID: tampered, UserHome: home(tampered), Connector: "codex",
			Error: "enterprise hooks: tamper: the managed DefenseClaw folder of this enrolled account holds an entry only a per-user DefenseClaw install leaves"},
	}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformFinish(context.Background(), &log, rows, time.Now())
	want := tampered + "," + plain
	for name, got := range map[string][]string{"cleanup": cleaned, "block report": collected, "Claude Code migration": probed} {
		if strings.Join(got, ",") != want {
			t.Errorf("%s ran for %v, want only the enrolled account and the account without a per-user install (%s); log:\n%s",
				name, got, want, log.String())
		}
	}
}
