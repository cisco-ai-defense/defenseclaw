// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubEnterpriseHookTokenSources(t *testing.T) (userCalls *[]string, scopedCalls *int) {
	t.Helper()
	origCfg := cfg
	origScoped, origScopedOTLP := enterpriseHookScopedTokenMinter, enterpriseHookScopedOTLPTokenMinter
	origUser, origUserLoader := enterpriseHookUserTokenMinter, enterpriseHookUserTokenLoader
	t.Cleanup(func() {
		cfg = origCfg
		enterpriseHookScopedTokenMinter, enterpriseHookScopedOTLPTokenMinter = origScoped, origScopedOTLP
		enterpriseHookUserTokenMinter, enterpriseHookUserTokenLoader = origUser, origUserLoader
	})
	users := []string{}
	scoped := 0
	enterpriseHookScopedTokenMinter = func(string, string) (string, error) { scoped++; return "connector-hook", nil }
	enterpriseHookScopedOTLPTokenMinter = func(string, string) (string, error) { scoped++; return "connector-otlp", nil }
	enterpriseHookUserTokenMinter = func(_, connectorName, identity string) (string, string, error) {
		users = append(users, "mint:"+connectorName+":"+identity)
		return "user-hook-" + identity, "user-otlp-" + identity, nil
	}
	enterpriseHookUserTokenLoader = func(_, connectorName, identity string) (string, string, error) {
		users = append(users, "load:"+connectorName+":"+identity)
		return "user-hook-" + identity, "user-otlp-" + identity, nil
	}
	return &users, &scoped
}

// The standalone profile (the Windows guardian passes the SID) renders
// per-user credentials; every other profile, Secure Client included, keeps
// the connector-scoped ones.
func TestEnterpriseHookTargetTokensFollowTheProfile(t *testing.T) {
	const sid = "S-1-5-21-1111-2222-3333-1001"
	users, scoped := stubEnterpriseHookTokenSources(t)

	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = "standalone"
	hook, otlp, err := enterpriseHookTargetTokens("/data", "codex", sid, true)
	if err != nil || hook != "user-hook-"+sid || otlp != "user-otlp-"+sid {
		t.Fatalf("standalone mint = %q %q %v", hook, otlp, err)
	}
	if _, _, err := enterpriseHookTargetTokens("/data", "codex", sid, false); err != nil {
		t.Fatal(err)
	}
	if len(*users) != 2 || (*users)[0] != "mint:codex:"+sid || (*users)[1] != "load:codex:"+sid || *scoped != 0 {
		t.Fatalf("standalone calls = %v scoped=%d", *users, *scoped)
	}

	*users = (*users)[:0]
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	hook, otlp, err = enterpriseHookTargetTokens("/data", "codex", sid, true)
	if err != nil || hook != "connector-hook" || otlp != "connector-otlp" || len(*users) != 0 || *scoped != 2 {
		t.Fatalf("Secure Client mint = %q %q %v users=%v scoped=%d", hook, otlp, err, *users, *scoped)
	}
}

func TestEnterpriseHookUserScopedTokensDeriveFromTheProtectedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows key custody needs the gateway service account")
	}
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEnterpriseHookUserScopedTokens(dataDir, "codex", "1001"); err == nil {
		t.Fatal("verification must not mint the per-user credential key")
	}
	hook, otlp, err := enterpriseHookUserScopedTokens(dataDir, "codex", "1001")
	if err != nil {
		t.Fatal(err)
	}
	key, err := connector.LoadUserScopedTokenKey(dataDir)
	if err != nil || key == "" {
		t.Fatalf("key = %v", err)
	}
	wantHook, _ := connector.UserScopedHookAPIToken(key, "codex", "1001")
	wantOTLP, _ := connector.UserScopedOTLPPathToken(key, connector.OTLPScopeCodex, "1001")
	if hook != wantHook || otlp != wantOTLP {
		t.Fatal("per-user credentials do not derive from the stored key")
	}
	loadedHook, loadedOTLP, err := loadEnterpriseHookUserScopedTokens(dataDir, "codex", "1001")
	if err != nil || loadedHook != hook || loadedOTLP != otlp {
		t.Fatalf("load = %v", err)
	}
	other, _, err := enterpriseHookUserScopedTokens(dataDir, "codex", "1002")
	if err != nil || other == hook {
		t.Fatalf("another uid must get another credential: %v", err)
	}
	if hook, otlp, err := enterpriseHookUserScopedTokens(dataDir, "devin", "1001"); err != nil || hook == "" || otlp != "" {
		t.Fatalf("a connector without an OTLP source: %q %q %v", hook, otlp, err)
	}
	for _, identity := range []string{"", "alice", "-1"} {
		if _, _, err := enterpriseHookUserScopedTokens(dataDir, "codex", identity); err == nil {
			t.Errorf("identity %q accepted", identity)
		}
	}
	info, err := os.Stat(filepath.Join(dataDir, "hooks", ".user-scoped-token.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key custody: %v %v", info, err)
	}
	if _, _, err := enterpriseHookUserScopedTokens("", "codex", "1001"); err == nil || !strings.Contains(err.Error(), "data_dir") {
		t.Fatalf("empty data dir: %v", err)
	}
}
