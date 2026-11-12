// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"path/filepath"
	"testing"
)

func pinStandaloneScope(t *testing.T, profile string) (home, config string) {
	t.Helper()
	base := t.TempDir()
	home = filepath.Join(base, "data")
	config = filepath.Join(base, "etc", "config.yaml")
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv(EnterpriseProfileEnv, profile)
	t.Setenv(WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGateway`)
	t.Setenv(managedHomeEnv, home)
	t.Setenv(managedConfigEnv, config)
	return home, config
}

// GAP-0762 / GAP-0766: the managed creation path applies to the data and
// config folders of a standalone deployment and nowhere else.
func TestStandaloneManagedTreeAccountScope(t *testing.T) {
	home, config := pinStandaloneScope(t, ProfileStandalone)
	for _, path := range []string{
		filepath.Join(home, "hooks"),
		filepath.Join(home, "acp", ".enterprise-enrollment.lock"),
		config + ".lock",
	} {
		if account, ok := StandaloneManagedTreeAccount(path); !ok || account == "" {
			t.Errorf("%s must be created in the managed protection", path)
		}
	}
	for _, path := range []string{
		filepath.Join(filepath.Dir(home), "Users", "alice", ".defenseclaw", "hooks"),
		home + "-other",
		filepath.Join(home, "..", "elsewhere"),
		"relative",
		"",
	} {
		if _, ok := StandaloneManagedTreeAccount(path); ok {
			t.Errorf("%q is outside the managed tree and must keep an ordinary object", path)
		}
	}
}

// Secure Client behaviour stays unchanged: its objects are not created by
// this path, and neither is anything in an unpinned or per-user process.
func TestStandaloneManagedTreeAccountExcludesSecureClientAndUnmanaged(t *testing.T) {
	home, _ := pinStandaloneScope(t, ProfileSecureClient)
	hooks := filepath.Join(home, "hooks")
	if _, ok := StandaloneManagedTreeAccount(hooks); ok {
		t.Error("the Secure Client profile must keep its ordinary directory")
	}
	t.Setenv(EnterpriseProfileEnv, "")
	if _, ok := StandaloneManagedTreeAccount(hooks); ok {
		t.Error("an unpinned profile resolves to Secure Client on Windows and must stay ordinary")
	}
	t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
	t.Setenv(DeploymentModeEnv, "")
	if _, ok := StandaloneManagedTreeAccount(hooks); ok {
		t.Error("a per-user (unmanaged) process must stay ordinary")
	}
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv(WindowsServiceAccountEnv, "")
	if _, ok := StandaloneManagedTreeAccount(hooks); ok {
		t.Error("without the gateway service pin nothing can be created for it")
	}
}

// GAP-0766: a lock beside the pinned config is judged as the config is; every
// other lock in the tree (the .env lock, the ACP locks) as a runtime file.
func TestLockFileKindFor(t *testing.T) {
	home, config := pinStandaloneScope(t, ProfileStandalone)
	if got := LockFileKindFor(config + ".lock"); got != ObjectConfigFile {
		t.Errorf("config lock kind = %s, want %s", got, ObjectConfigFile)
	}
	for _, path := range []string{
		filepath.Join(home, ".env.lock"),
		filepath.Join(home, "acp", ".enterprise-credentials.lock"),
	} {
		if got := LockFileKindFor(path); got != ObjectRuntimeFile {
			t.Errorf("%s kind = %s, want %s", path, got, ObjectRuntimeFile)
		}
	}
}
