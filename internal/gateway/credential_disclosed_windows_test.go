// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// grantEveryoneReadForTest adds an Everyone read entry to path's DACL.
func grantEveryoneReadForTest(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func pinSecureClientHostForTest(t *testing.T, verified bool) {
	t.Helper()
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	previous := connector.SecureClientDeploymentVerified
	previousHost, previousPath := managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified
	t.Cleanup(func() {
		connector.SecureClientDeploymentVerified = previous
		managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified = previousHost, previousPath
	})
	connector.SecureClientDeploymentVerified = func() bool { return verified }
	managed.SecureClientHostVerified = func() bool { return verified }
	managed.SecureClientProcessPathVerified = func(string) bool { return verified }
}

// GAP-0566 review 1: outside a verified Secure Client host, a cached OTLP
// path token whose file every local account can read stops authenticating at
// the next validation instead of riding the drift fallback.
func TestOTLPPathTokenCacheDroppedWhenEveryLocalAccountCanRead(t *testing.T) {
	pinSecureClientHostForTest(t, false)
	dataDir := t.TempDir()
	token, err := connector.EnsureOTLPPathToken(dataDir, connector.OTLPScopeCodex)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken: %v", err)
	}
	cfg := &config.Config{DataDir: dataDir}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: token})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != token {
		t.Fatal("initial OTLP token lookup failed")
	}
	path, err := connector.OTLPPathTokenFilePath(dataDir, connector.OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	grantEveryoneReadForTest(t, path)
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != "" {
		t.Fatal("the gateway kept authenticating an OTLP token every local account can read")
	}
	assertScopedOTLPAuth(t, api, token, http.StatusUnauthorized)
}

// GAP-0566 review 1: the same for the hook API token, and Ensure rotates it.
// On a verified Secure Client host the extra reader stays accepted drift.
func TestHookAPITokenDisclosedIsDroppedAndRotated(t *testing.T) {
	t.Run("outside secure client", func(t *testing.T) {
		pinSecureClientHostForTest(t, false)
		dataDir := t.TempDir()
		old, err := connector.EnsureHookAPIToken(dataDir, "codex")
		if err != nil {
			t.Fatalf("EnsureHookAPIToken: %v", err)
		}
		api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
		api.SetHookAPITokens(map[string]string{"codex": old})
		if !api.hookAPITokenMatches("codex", old) {
			t.Fatal("provisioned hook token was rejected")
		}
		path, err := connector.HookAPITokenFilePath(dataDir, "codex")
		if err != nil {
			t.Fatal(err)
		}
		grantEveryoneReadForTest(t, path)
		if api.hookAPITokenMatches("codex", old) {
			t.Fatal("the gateway kept authenticating a hook token every local account can read")
		}
		rotated, err := connector.EnsureHookAPIToken(dataDir, "codex")
		if err != nil {
			t.Fatalf("EnsureHookAPIToken did not rotate the disclosed token: %v", err)
		}
		if rotated == "" || rotated == old {
			t.Fatal("EnsureHookAPIToken kept the disclosed value")
		}
		if loaded, err := connector.LoadHookAPIToken(dataDir, "codex"); err != nil || loaded != rotated {
			t.Fatalf("load rotated hook token: matched=%v err=%v", loaded == rotated, err)
		}
		if api.hookAPITokenMatches("codex", old) || !api.hookAPITokenMatches("codex", rotated) {
			t.Fatal("the gateway did not move to the rotated hook token")
		}
	})
	t.Run("verified secure client keeps the drift decision", func(t *testing.T) {
		pinSecureClientHostForTest(t, true)
		dataDir := t.TempDir()
		token, err := connector.EnsureHookAPIToken(dataDir, "codex")
		if err != nil {
			t.Fatalf("EnsureHookAPIToken: %v", err)
		}
		api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
		api.SetHookAPITokens(map[string]string{"codex": token})
		path, err := connector.HookAPITokenFilePath(dataDir, "codex")
		if err != nil {
			t.Fatal(err)
		}
		grantEveryoneReadForTest(t, path)
		if !api.hookAPITokenMatches("codex", token) {
			t.Fatal("Secure Client stopped accepting a hook token with an extra reader")
		}
	})
}

func TestHookAPITokenPerUserOnSecureClientHostIsDroppedAndRotated(t *testing.T) {
	pinSecureClientHostForTest(t, true)
	managed.SecureClientProcessPathVerified = func(string) bool { return false }
	dataDir := t.TempDir()
	old, err := connector.EnsureHookAPIToken(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	api.SetHookAPITokens(map[string]string{"codex": old})
	path, err := connector.HookAPITokenFilePath(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	grantEveryoneReadForTest(t, path)
	if api.hookAPITokenMatches("codex", old) {
		t.Fatal("a broadly readable per-user hook token remained authorized")
	}
	rotated, err := connector.EnsureHookAPIToken(dataDir, "codex")
	if err != nil || rotated == "" || rotated == old {
		t.Fatalf("per-user hook token rotation failed: rotated=%v err=%v", rotated != old, err)
	}
}
