//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func longRehomeReportTestPath(name string) string {
	return filepath.Join("/tmp", strings.Repeat("a", 55), strings.Repeat("b", 55),
		strings.Repeat("c", 55), strings.Repeat("d", 55), strings.Repeat(name, 8))
}

func TestGuardianRehomeLedgerAndWarningKeepLongHomeRemedy(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	oldHome, currentHome := longRehomeReportTestPath("old"), longRehomeReportTestPath("new")
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: 31415, GID: 31415, Home: currentHome}
	entry := enterpriseHookUserCleanup{Connector: "opencode", User: "sample-user", UID: 31415,
		UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw")}
	now := time.Now()
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
		t.Fatal(err)
	}
	f.writeManifest(t)
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &log, manifest,
		enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, now); err != nil {
		t.Fatal(err)
	}
	remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
	const remedy = "fix the account's home to an existing account-owned directory without symlinks or group/other write, or remove the account, then rerun"
	if err != nil || len(remaining) != 1 || len(remaining[0].LastError) > enterpriseHookUserCleanupErrorMax ||
		!strings.Contains(remaining[0].LastError, remedy) || !strings.Contains(log.String(), remedy) ||
		!strings.Contains(remaining[0].LastError, "/.../") {
		t.Fatalf("long-home ledger or warning lost remedy: remaining %+v, %v, log %q", remaining, err, log.String())
	}
}

func TestUserCleanupOtherFailureTextIsByteIdentical(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "nil"},
		{name: "short", err: errors.New("agent config remains")},
		{name: "whitespace", err: errors.New("agent\n config\t remains")},
		{name: "long", err: errors.New(strings.Repeat("x", 600))},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: 1001}
			remaining, result := runEnterpriseHookUserCleanups(context.Background(), []enterpriseHookUserCleanup{entry},
				func(context.Context, enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
					return enterpriseHookUserCleanupFailed, test.err
				}, time.Now())
			want := "cleanup failed"
			if test.err != nil {
				want = test.err.Error()
			}
			want = boundedEnterpriseHookUserCleanupText(want)
			if len(remaining) != 1 || remaining[0].LastError != want ||
				len(result.Failed) != 1 || result.Failed[0] != "hermes/sample-user: "+want {
				t.Fatalf("non-rehome failure changed: remaining %+v, result %+v, want %q", remaining, result, want)
			}
		})
	}
}

func TestTypedRehomeFailuresKeepTheirRemediesWithLongHomes(t *testing.T) {
	oldHome, currentHome := longRehomeReportTestPath("old"), longRehomeReportTestPath("new")
	changed := &enterpriseHookTargetHomeChangedError{name: "sample-user", home: oldHome, directoryHome: currentHome}
	for _, test := range []struct {
		name, remedy string
		err          error
	}{
		{name: "home changed", err: enterpriseHookRehomedCleanupError(changed, "current home is unavailable"),
			remedy: "fix the account's home to an existing account-owned directory without symlinks or group/other write, or remove the account, then rerun"},
		{name: "old home kept", err: &enterpriseHookCleanupOldHomeKeptError{name: "sample-user", connector: "opencode",
			home: oldHome, currentHome: currentHome, reason: "owner cannot be verified"},
			remedy: "fix owner/permissions and rerun"},
		{name: "unverified current home", err: &enterpriseHookCleanupUnverifiedError{changed: changed, connector: "opencode",
			home: currentHome, dataDir: filepath.Join(currentHome, ".defenseclaw"),
			path:       filepath.Join(currentHome, ".config", "opencode", "plugins", "defenseclaw.js"),
			configPath: filepath.Join(currentHome, ".config", "opencode", "plugins", "defenseclaw.js"),
			reason:     "DefenseClaw entries remain"},
			remedy: "delete the stale copied receipt under"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := enterpriseHookUserCleanupFailureText(test.err)
			if len(got) > enterpriseHookUserCleanupErrorMax || !strings.Contains(got, test.remedy) ||
				!strings.Contains(got, "rerun") {
				t.Fatalf("typed failure lost bounded remedy: %d bytes, %q", len(got), got)
			}
		})
	}
}

func TestUnreportedRehomeWarningNamesHomeAsDirectory(t *testing.T) {
	oldHome, currentHome := longRehomeReportTestPath("old"), longRehomeReportTestPath("new")
	changed := &enterpriseHookTargetHomeChangedError{name: "sample-user", home: oldHome, directoryHome: currentHome}
	err := &enterpriseHookCleanupUnverifiedError{changed: changed, connector: "opencode",
		home: currentHome, dataDir: filepath.Join(currentHome, ".defenseclaw"),
		path: currentHome, configPath: currentHome, reason: "the worker did not report the paths it found"}
	got := enterpriseHookUserCleanupFailureText(err)
	if len(got) > enterpriseHookUserCleanupErrorMax || !strings.Contains(got, "config in the home") ||
		strings.Contains(got, "config at "+currentHome) || !strings.Contains(got, "stale copied receipt") ||
		!strings.Contains(got, "rerun") {
		t.Fatalf("missing-report warning misstated the home or lost remedy: %q", got)
	}
}

func TestRemoveAllRehomeReportKeepsTheFullRemedyWithLongHomes(t *testing.T) {
	const remedy = "fix the account's home to an existing account-owned directory without symlinks or group/other write, or remove the account, then rerun"
	for _, test := range []struct {
		name, oldHome, currentHome string
	}{
		{name: "long", oldHome: longRehomeReportTestPath("old"), currentHome: longRehomeReportTestPath("new")},
		{name: "short", oldHome: "/tmp/sample-old", currentHome: "/tmp/sample-current"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			uid, gid := 31415, 31415
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: test.currentHome}
			entry := enterpriseHookUserCleanup{Connector: "opencode", User: "sample-user", UID: uid,
				UserHome: test.oldHome, DataDir: filepath.Join(test.oldHome, ".defenseclaw")}
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, time.Now()); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
			if report.Removed != 0 || len(report.Failed) != 1 || skip[uid] != enterpriseHookPurgeSkipFailed {
				t.Fatalf("report = %+v, skip = %+v", report, skip)
			}
			got := report.Failed[0]
			if test.name == "long" {
				if len(test.oldHome) < 240 || len(test.currentHome) < 240 {
					t.Fatalf("home paths are not long enough: %d and %d", len(test.oldHome), len(test.currentHome))
				}
				if !strings.Contains(got, remedy) || !strings.Contains(got, "/.../") ||
					strings.Contains(got, test.oldHome) || strings.Contains(got, test.currentHome) || len(got) >= 800 {
					t.Fatalf("long-home report lost remedy or bound: %d bytes, %q", len(got), got)
				}
				return
			}
			_, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &strings.Builder{}, entry, resolver)
			if err == nil {
				t.Fatal("short-home fixture did not fail")
			}
			want := "sample-user/opencode: " + boundedEnterpriseHookUserCleanupText(err.Error())
			if got != want {
				t.Fatalf("short-home report = %q, want byte-identical %q", got, want)
			}
		})
	}
}

// A worker reason can carry the words of the home-check separator. The
// formatter then keeps the remedy of the unverified form instead of
// clipping it as the trailing reason (GAP-0634). Config paths up to 180
// bytes stay whole, so the ledger text runs past its bound.
func TestRehomeFailureTextKeepsRemedyWhenReasonHoldsTheSeparator(t *testing.T) {
	for size := 40; size <= 240; size += 10 {
		oldHome := "/home/old" + strings.Repeat("x", size)
		currentHome := "/home/cur" + strings.Repeat("x", size)
		changed := &enterpriseHookTargetHomeChangedError{name: "sample-user", home: oldHome, directoryHome: currentHome}
		plugin := currentHome + "/.config/opencode/plugins/defenseclaw.js"
		for _, reason := range []string{"DefenseClaw entries remain: x", "DefenseClaw entries remain: a; current home check: b", "a then rerun; current home check: b"} {
			err := &enterpriseHookCleanupUnverifiedError{changed: changed, connector: "opencode", dataDir: currentHome + "/.defenseclaw",
				home: currentHome, path: plugin, configPath: plugin, reason: reason}
			for name, text := range map[string]string{"ledger": enterpriseHookUserCleanupFailureText(err), "report": enterpriseHookRehomedReportReason(err)} {
				if !strings.HasSuffix(text, "and rerun") || !strings.Contains(text, "stale copied receipt") {
					t.Errorf("home size %d, %s text for reason %q lost the remedy: %q", size, name, reason, text)
				}
			}
		}
	}
}
