// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-4 GAP-0596: the agent identity of a verified SID records the UPN
// in the directory facts the hook path cached for that SID, as a Linux or
// macOS identity does for a uid, so enterprise windows agent-identities
// names it.
func TestAgentIdentityOfASIDRecordsTheCachedUPN(t *testing.T) {
	agentIdentityTestSetup(t)
	const sid = "S-1-5-21-1870-400-596-1105"
	peerDirectoryCache()
	previous := windowsDirectories
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example.com",
			UPN: "ivan@corp.example.com", ResolvedAt: time.Now(),
		}, nil
	})
	t.Cleanup(func() { windowsDirectories = previous })
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the hook path did not cache the SID's facts")
	}
	ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strings.ToLower(sid))
	facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"})
	if facts.ID == "" || facts.UserUPN != "ivan@corp.example.com" || facts.UPNUnavailable {
		t.Fatalf("agent identity %q recorded UPN %q, want ivan@corp.example.com", facts.ID, facts.UserUPN)
	}

	// After a gateway restart an AD lookup can still be running. That is
	// distinct from a local account whose verified facts have no UPN.
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: time.Now()}, nil
	})
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the AD facts did not cache")
	}
	if cold := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"}); cold.UserUPN != "" || !cold.UPNUnavailable {
		t.Fatalf("cold AD UPN = %q, unavailable %t; want unavailable", cold.UserUPN, cold.UPNUnavailable)
	}
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
			GuardianRecord: true, ResolvedAt: time.Now()}, nil
	})
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the current guardian facts did not cache")
	}
	if missing := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"}); missing.UserUPN != "" || !missing.UPNUnavailable {
		t.Fatalf("current AD record without a UPN = %q, unavailable %t; want unavailable", missing.UserUPN, missing.UPNUnavailable)
	}
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, ResolvedAt: time.Now()}, nil
	})
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the local facts did not cache")
	}
	if local := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"}); local.UserUPN != "" || local.UPNUnavailable {
		t.Fatalf("local UPN = %q, unavailable %t; want verified absence", local.UserUPN, local.UPNUnavailable)
	}
}

func TestAgentIdentityUPNOmitsExpiredAndFailedDirectoryFacts(t *testing.T) {
	agentIdentityTestSetup(t)
	const sid = "S-1-5-21-1870-400-596-1105"
	peerDirectoryCache()
	previous := windowsDirectories
	t.Cleanup(func() { windowsDirectories = previous })
	ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strings.ToLower(sid))
	for _, tc := range []struct {
		name string
		fail bool
	}{
		{"expired facts", false},
		{"failed refresh", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			calls := 0
			windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
				calls++
				if calls > 1 {
					return useridentity.DirectoryFacts{}, errors.New("directory unavailable")
				}
				return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
					UPN: "ivan@corp.example.com", ResolvedAt: now}, nil
			})
			windowsDirectories.now = func() time.Time { return now }
			if _, ok := windowsDirectories.get(sid, true); !ok {
				t.Fatal("initial AD facts did not cache")
			}
			if tc.fail {
				now = now.Add(time.Second)
				windowsDirectories.invalidate()
				if stale, ok := windowsDirectories.get(sid, true); !ok || stale.UPN == "" {
					t.Fatalf("policy cache did not retain its last facts: %+v, %t", stale, ok)
				}
			} else {
				now = now.Add(identityDirectoryTTL)
			}
			facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"})
			if facts.ID == "" || facts.UserUPN != "" || !facts.UPNUnavailable {
				t.Fatalf("agent identity after %s = %+v; want no old UPN", tc.name, facts)
			}
		})
	}
}

// Hook identity recording precedes profile lookup. A guardian record that
// changes while the directory cache is still valid must reach this hook's row.
func TestAgentIdentitySIDUsesCurrentGuardianUPNBeforeProfileLookup(t *testing.T) {
	agentIdentityTestSetup(t)
	const sid = "S-1-5-21-1870-400-596-1105"
	peerDirectoryCache()
	previousCache, previousDir, previousValidate := windowsDirectories, currentIdentitySpoolDir(), validateManagedGuardianAuthorization
	t.Cleanup(func() {
		windowsDirectories = previousCache
		setIdentitySpoolDir(previousDir)
		validateManagedGuardianAuthorization = previousValidate
	})
	for _, tc := range []struct {
		name, current string
		publish       bool
	}{
		{"UPN changed", "renamed@corp.example.com", true},
		{"UPN removed", "", true},
		{"guardian record withdrawn", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			setIdentitySpoolDir(dir)
			validateManagedGuardianAuthorization = func(string, string) error { return nil }
			windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
				return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
					UPN: "old@corp.example.com", GuardianRecord: true,
					Groups: []string{"S-1-5-21-1870-400-596-513"}, ResolvedAt: time.Now()}, nil
			})
			if _, ok := windowsDirectories.get(sid, true); !ok {
				t.Fatal("old guardian facts did not cache")
			}
			if tc.publish {
				data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
					Key: sid, UpdatedAt: time.Now().Add(-time.Second), Facts: useridentity.DirectoryFacts{
						Directory: useridentity.DirectoryActiveDirectory, UPN: tc.current,
						Groups: []string{"S-1-5-21-1870-400-596-513"},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			upn, known := agentIdentityAccountUPN(sid)
			if upn != tc.current || known != (tc.current != "") {
				t.Fatalf("UPN before profile lookup = %q, known %t; want %q, known %t", upn, known, tc.current, tc.current != "")
			}
			ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strings.ToLower(sid))
			facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"})
			if facts.ID == "" || facts.UserUPN != tc.current || facts.UPNUnavailable != (tc.current == "") {
				t.Fatalf("hook identity before profile lookup = %+v; want UPN %q, unavailable %t", facts, tc.current, tc.current == "")
			}
		})
	}
}

// A guardian record may keep a last verified UPN for policy matching while
// TranslateNameW is unavailable. It is not a current fact for the identity row.
func TestAgentIdentitySIDOmitsKeptGuardianUPN(t *testing.T) {
	agentIdentityTestSetup(t)
	const sid = "S-1-5-21-1870-400-596-1105"
	dir := t.TempDir()
	previousDir, previousValidate := currentIdentitySpoolDir(), validateManagedGuardianAuthorization
	setIdentitySpoolDir(dir)
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() {
		setIdentitySpoolDir(previousDir)
		validateManagedGuardianAuthorization = previousValidate
	})
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: sid, UpdatedAt: time.Now().UTC(), UPNSource: enterprisehooks.UPNSourceTranslateName,
		UPNKeptSince: time.Now().UTC().Add(-time.Minute),
		Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
			UPN: "alice@corp.example.com", Principal: "alice@corp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if upn, known := agentIdentityAccountUPN(sid); upn != "" || known {
		t.Fatalf("identity row UPN = %q, known %t; want no current UPN", upn, known)
	}
	ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strings.ToLower(sid))
	facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"})
	if facts.UserUPN != "" || !facts.UPNUnavailable {
		t.Fatalf("hook row facts = %+v; want an unavailable current UPN", facts)
	}
}

func TestAgentIdentitySIDOmitsKeptDirectoryCacheUPN(t *testing.T) {
	agentIdentityTestSetup(t)
	const sid = "S-1-5-21-1870-400-596-1105"
	peerDirectoryCache()
	previousCache, previousDir := windowsDirectories, currentIdentitySpoolDir()
	setIdentitySpoolDir("")
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
			UPN: "alice@corp.example.com", UPNKept: true, ResolvedAt: time.Now()}, nil
	})
	t.Cleanup(func() {
		windowsDirectories = previousCache
		setIdentitySpoolDir(previousDir)
	})
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("kept directory facts did not cache")
	}
	if upn, known := agentIdentityAccountUPN(sid); upn != "" || known {
		t.Fatalf("identity row UPN = %q, known %t; want no current UPN", upn, known)
	}
}
