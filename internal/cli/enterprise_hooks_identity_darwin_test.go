//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubGeneratedUIDs(t *testing.T, guids map[string]string) *int {
	t.Helper()
	calls := 0
	previous := enterpriseHookGeneratedUIDLookup
	enterpriseHookGeneratedUIDLookup = func(name string) (string, error) {
		calls++
		if guid, ok := guids[name]; ok {
			return guid, nil
		}
		return "", errors.New("no such user")
	}
	enterpriseHookGeneratedUIDs.Lock()
	enterpriseHookGeneratedUIDs.entries = map[string]enterpriseHookGeneratedUIDEntry{}
	enterpriseHookGeneratedUIDs.Unlock()
	t.Cleanup(func() { enterpriseHookGeneratedUIDLookup = previous })
	return &calls
}

func captureCLIResilience(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	previous := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, managed.FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() { managed.ReportResilienceEvent = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func TestDarwinLedgerIdentityDoesNotCarryOverToAReusedName(t *testing.T) {
	const oldGUID = "11111111-2222-3333-4444-555555555555"
	const newGUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	calls := stubGeneratedUIDs(t, map[string]string{"alice": oldGUID})

	original, err := resolveEnterpriseHookTargetValues("", "/Users/alice", 501, 20, "", "")
	if err != nil || original.sid != "" {
		t.Fatalf("home-only target: sid=%q err=%v", original.sid, err)
	}
	identity, err := enterpriseHookPlatformTargetIdentity("alice", 501)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "uid:501/guid:"+oldGUID {
		t.Fatalf("identity = %q", identity)
	}
	if _, err := enterpriseHookPlatformTargetIdentity("alice", 501); err != nil || *calls != 1 {
		t.Fatalf("cached lookup: calls=%d err=%v", *calls, err)
	}
	protected := enterpriseHookReconcileRow{User: "alice", UserHome: "/Users/alice", SID: identity, Connector: "claudecode", OK: true}

	// Same account: matches.
	if !enterpriseHookRowMatches(protected, "alice", "/Users/alice", identity, "claudecode") {
		t.Fatal("same account does not match its ledger row")
	}
	// The name was reused by a new account (new GeneratedUID, maybe the same
	// uid): no inherited protection.
	reused := enterpriseHookDarwinIdentity(501, newGUID)
	if enterpriseHookRowMatches(protected, "alice", "/Users/alice", reused, "claudecode") {
		t.Fatal("a reused short name inherited the previous account's protection")
	}
	if enterpriseHookProtectedTargetKey(protected) == enterpriseHookProtectedTargetKey(
		enterpriseHookReconcileRow{User: "alice", SID: reused, Connector: "claudecode"},
	) {
		t.Fatal("ledger keys of two accounts with the same name collide")
	}
}

func TestDarwinLegacyLedgerRowMatchesByNameOnce(t *testing.T) {
	identity := enterpriseHookDarwinIdentity(501, "11111111-2222-3333-4444-555555555555")
	legacy := enterpriseHookReconcileRow{User: "alice", UserHome: "/Users/alice", Connector: "codex", OK: true}
	if !enterpriseHookRowMatches(legacy, "alice", "/Users/alice", identity, "codex") {
		t.Fatal("a ledger row from before identities were recorded no longer matches")
	}
	if enterpriseHookRowMatches(legacy, "alice", "/Users/other", identity, "codex") {
		t.Fatal("a legacy row matched a different home")
	}
	if enterpriseHookRowMatches(legacy, "bob", "/Users/alice", identity, "codex") {
		t.Fatal("a legacy row matched a different name")
	}
}

func TestDarwinIdentityLookupFailureFailsOnlyThatTarget(t *testing.T) {
	stubGeneratedUIDs(t, map[string]string{})
	if _, err := enterpriseHookPlatformTargetIdentity("ghost", 777); err == nil {
		t.Fatal("a failed GeneratedUID lookup was accepted")
	}
	stubGeneratedUIDs(t, map[string]string{"weird": "not-a-guid"})
	if _, err := enterpriseHookPlatformTargetIdentity("weird", 778); err == nil {
		t.Fatal("a malformed GeneratedUID was accepted")
	}
}

func TestDarwinManifestSkippedRowsLoggedOncePerStreak(t *testing.T) {
	lines := captureCLIResilience(t)
	enterpriseHookManifestRowSkips.Lock()
	enterpriseHookManifestRowSkips.logged = map[string]struct{}{}
	enterpriseHookManifestRowSkips.Unlock()
	skipped := []enterprisehooks.ManifestRowSkip{{Index: 2, Reason: "enterprise hooks: target 2 requires connector"}}

	reportEnterpriseHookManifestSkippedRowsPlatform("/opt/x/hook-guardian/targets.yaml", skipped)
	reportEnterpriseHookManifestSkippedRowsPlatform("/opt/x/hook-guardian/targets.yaml", skipped)
	got := lines()
	if len(got) != 1 || !strings.HasPrefix(got[0], `defenseclaw_skip path="/opt/x/hook-guardian/targets.yaml"`) ||
		!strings.Contains(got[0], `unit="row2"`) {
		t.Fatalf("lines = %v", got)
	}
	reportEnterpriseHookManifestSkippedRowsPlatform("/opt/x/hook-guardian/targets.yaml", nil)
	reportEnterpriseHookManifestSkippedRowsPlatform("/opt/x/hook-guardian/targets.yaml", skipped)
	if len(lines()) != 2 {
		t.Fatalf("a new streak was not logged: %v", lines())
	}
}

func TestDarwinWatchFailureIsDegradedNotFatal(t *testing.T) {
	lines := captureCLIResilience(t)
	enterpriseHookWatchDegraded.Lock()
	enterpriseHookWatchDegraded.last = ""
	enterpriseHookWatchDegraded.Unlock()
	err := errors.New("watch /Users/a/.claude: too many open files")
	if !enterpriseHookWatchFailureToleratedPlatform(err) || !enterpriseHookWatchFailureToleratedPlatform(err) {
		t.Fatal("a watch failure failed the pass")
	}
	got := lines()
	if len(got) != 1 || !strings.Contains(got[0], `subsystem="watch"`) || !strings.HasPrefix(got[0], managed.MarkerDegraded) {
		t.Fatalf("lines = %v", got)
	}
}
