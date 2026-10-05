// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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
	// A staged next key alone is never rendered from: rendering and
	// verification derive from it only while the guardian's root-only
	// prepare record names it as next and the committed key as previous,
	// and never from the committed key's bytes.
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	staged := strings.Repeat("ab", 32)
	if err := os.WriteFile(filepath.Join(dataDir, "hooks", ".user-scoped-token.key.next"), []byte(staged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.Mkdir(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantStaged, _ := connector.UserScopedHookAPIToken(staged, "codex", "1001")
	for _, phase := range []string{"", enterprisehooks.CredentialPhaseRollback, enterprisehooks.CredentialPhasePrepare} {
		if phase != "" {
			record, _ := json.Marshal(enterprisehooks.CredentialTransaction{
				Version: enterprisehooks.CredentialTransactionVersion, OperationID: strings.Repeat("0", 32), Phase: phase,
				ManifestSHA256: strings.Repeat("d", 64), PreviousKeyID: connector.UserScopedTokenKeyFingerprint(key), NextKeyID: connector.UserScopedTokenKeyFingerprint(staged),
			})
			if err := os.WriteFile(filepath.Join(authDir, managed.HookGuardianCredentialTransactionFile), record, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want := hook
		if phase == enterprisehooks.CredentialPhasePrepare {
			want = wantStaged
		}
		for name, derive := range map[string]func(string, string, string) (string, string, error){
			"mint": enterpriseHookUserScopedTokens, "load": loadEnterpriseHookUserScopedTokens,
		} {
			if got, _, err := derive(dataDir, "codex", "1001"); err != nil || got != want {
				t.Fatalf("%s with a staged key and record %q: derived from the staged key=%v err=%v", name, phase, got == wantStaged, err)
			}
		}
	}
	if committed, err := connector.LoadUserScopedTokenKey(dataDir); err != nil || committed != key {
		t.Fatalf("rendering from the staged key changed the committed key: %v", err)
	}
	if _, _, err := enterpriseHookUserScopedTokens("", "codex", "1001"); err == nil || !strings.Contains(err.Error(), "data_dir") {
		t.Fatalf("empty data dir: %v", err)
	}
}
