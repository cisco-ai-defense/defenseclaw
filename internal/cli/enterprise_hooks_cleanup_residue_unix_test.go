//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A Remove and a Purge in one worker job: a Remove that leaves a DefenseClaw
// entry the agent still loads, or that cannot be checked, keeps the
// account's state and its backup receipts for the rerun. Only a removal
// checked clean lets the purge run (GAP-0632).
func TestEnterpriseHookWorkerPurgeKeepsStateAfterUncleanRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previousPath := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = ""
	previousStop, previousRemover := enterpriseHookWorkerStopPerUser, enterpriseHookWorkerRemover
	t.Cleanup(func() {
		connector.OpenCodePluginPathOverride = previousPath
		enterpriseHookWorkerStopPerUser, enterpriseHookWorkerRemover = previousStop, previousRemover
	})
	enterpriseHookWorkerStopPerUser = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }

	install := func(t *testing.T) (string, string, string, enterprisehooks.InstallOptions) {
		t.Helper()
		home := t.TempDir()
		opts := enterprisehooks.InstallOptions{
			ConnectorName: "opencode", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
			APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
			APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
			GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "2.1.4",
			Registry: connector.NewDefaultRegistry(),
		}
		if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
		receipt := filepath.Join(home, ".defenseclaw", "connector_backups", "opencode", "config.json")
		if _, err := os.Stat(receipt); err != nil {
			t.Fatal(err)
		}
		return home, plugin, receipt, opts
	}
	run := func(t *testing.T, home string, opts enterprisehooks.InstallOptions) []enterpriseHookWorkerTargetResult {
		t.Helper()
		purge := enterpriseHookWorkerTarget{Index: 1, Mode: enterpriseHookWorkerModePurge, Options: enterpriseHookWorkerOptions{
			UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: filepath.Join(home, ".defenseclaw"),
		}}
		request := enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(), Targets: []enterpriseHookWorkerTarget{
			{Index: 0, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptionsFrom(opts)}, purge,
		}}
		results := runEnterpriseHookWorkerApply(context.Background(), request).Targets
		if len(results) != 2 {
			t.Fatalf("worker answered %d targets: %+v", len(results), results)
		}
		if err := validateEnterpriseHookWorkerRemoveReport(results[0]); err != nil {
			t.Fatalf("invalid remove report %+v: %v", results[0], err)
		}
		return results
	}

	t.Run("edited plugin remains", func(t *testing.T) {
		home, plugin, receipt, opts := install(t)
		original, err := os.ReadFile(plugin)
		if err != nil {
			t.Fatal(err)
		}
		edited := append(append([]byte(nil), original...), []byte("\n// operator edit\n")...)
		if err := os.WriteFile(plugin, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		results := run(t, home, opts)
		if !results[0].OK || !results[0].PathsReported || results[0].Remaining == "" {
			t.Fatalf("remove did not report the edited plugin: %+v", results[0])
		}
		if results[1].OK || results[1].Purged != nil ||
			!strings.Contains(results[1].Error, "kept the per-user state") ||
			!strings.Contains(results[1].Error, "DefenseClaw entries remain") {
			t.Fatalf("purge ran after a removal left an entry: %+v", results[1])
		}
		if _, err := os.Stat(receipt); err != nil {
			t.Fatalf("the purge deleted the backup receipt: %v", err)
		}
		if data, err := os.ReadFile(plugin); err != nil || !bytes.Equal(data, edited) {
			t.Fatalf("the edited plugin changed: %v", err)
		}
	})

	t.Run("unverified removal", func(t *testing.T) {
		home := t.TempDir()
		dataDir := filepath.Join(home, ".defenseclaw")
		receipts := filepath.Join(dataDir, "connector_backups", "opencode")
		if err := os.MkdirAll(receipts, 0o700); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(map[string]interface{}{"version": 1, "connector": "opencode", "logical_name": "relative", "path": "relative/config"})
		if err != nil {
			t.Fatal(err)
		}
		receipt := filepath.Join(receipts, "relative.json")
		if err := os.WriteFile(receipt, data, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { enterpriseHookWorkerRemover = previousRemover })
		enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error { return nil }
		opts := enterprisehooks.InstallOptions{ConnectorName: "opencode", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
			DataDir: dataDir, Registry: connector.NewDefaultRegistry()}
		results := run(t, home, opts)
		if !results[0].OK || results[0].PathsReported || results[0].Unverified == "" {
			t.Fatalf("remove did not stay unverified: %+v", results[0])
		}
		if results[1].OK || !strings.Contains(results[1].Error, "could not be checked") {
			t.Fatalf("purge ran after an unverified removal: %+v", results[1])
		}
		if _, err := os.Stat(receipt); err != nil {
			t.Fatalf("the purge deleted the receipt: %v", err)
		}
	})

	t.Run("clean removal purges", func(t *testing.T) {
		home, plugin, _, opts := install(t)
		results := run(t, home, opts)
		if !results[0].OK || !results[0].PathsReported || results[0].Remaining != "" {
			t.Fatalf("clean removal = %+v", results[0])
		}
		if !results[1].OK || results[1].Purged == nil || !results[1].Purged.Data {
			t.Fatalf("purge after a clean removal = %+v", results[1])
		}
		if _, err := os.Lstat(filepath.Join(home, ".defenseclaw")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the per-user state remains: %v", err)
		}
		if _, err := os.Lstat(plugin); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the plugin remains: %v", err)
		}
	})
}

// A re-homed row ends only when its recorded home is clean too. The current
// home is clean (its copied plugin is DefenseClaw's own and the stale copied
// receipt is gone), but a plugin the operator edited in the recorded home
// survives the teardown there, and an agent run with that home still loads
// it. The row stays Failed with the path, and remove-all does not count it
// removed (GAP-0625).
func TestStandaloneCleanupRecordedHomeEditedPluginKeepsRow(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	copiedReceipt := filepath.Join(c.currentHome, ".defenseclaw", "connector_backups", "opencode", "config.json")
	if err := os.Remove(copiedReceipt); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(c.oldPlugin)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte(nil), original...), []byte("\n// operator edit\n")...)
	if err := os.WriteFile(c.oldPlugin, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
	if outcome != enterpriseHookUserCleanupFailed || err == nil ||
		!strings.Contains(err.Error(), c.oldHome) || !strings.Contains(err.Error(), "DefenseClaw entries remain") ||
		!strings.Contains(err.Error(), "rerun") {
		t.Fatalf("recorded-home residue cleanup = %v, %v; want a kept row naming the recorded home", outcome, err)
	}
	t.Logf("kept row: %v", err)
	if _, statErr := os.Lstat(c.newPlugin); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the current home still loads the copied plugin: %v", statErr)
	}
	if data, readErr := os.ReadFile(c.oldPlugin); readErr != nil || !bytes.Equal(data, edited) {
		t.Fatalf("the operator-edited plugin changed: %v", readErr)
	}
	if _, statErr := os.Stat(c.oldReceipt); statErr != nil {
		t.Fatalf("the edited plugin's receipt was lost: %v", statErr)
	}

	if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	skip := runEnterpriseHookPendingCleanupsWith(cmd, &report, map[int]*enterpriseHookWorkerJob{}, c.resolver)
	if report.Removed != 0 || len(report.Failed) != 1 || !strings.Contains(report.Failed[0], c.oldHome) ||
		skip[c.entry.UID] != enterpriseHookPurgeSkipFailed {
		t.Fatalf("remove-all counted the recorded-home residue removed: report %+v, skip %+v", report, skip)
	}
}
