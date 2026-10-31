//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func copyRehomedTestTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dest := filepath.Join(to, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			return os.MkdirAll(dest, info.Mode().Perm())
		case entry.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, dest)
		case entry.Type().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(dest, data, info.Mode().Perm())
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

type rehomedOpenCodeCase struct {
	fixture              *standaloneFixture
	resolver             standaloneTestResolver
	entry                enterpriseHookUserCleanup
	oldHome, currentHome string
	oldPlugin, newPlugin string
	oldReceipt           string
	oldEditedBytes       []byte
}

func setupRehomedOpenCodeCase(t *testing.T, edited, move bool) rehomedOpenCodeCase {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previous := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = ""
	t.Cleanup(func() { connector.OpenCodePluginPathOverride = previous })
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	homes, err := os.MkdirTemp(userHome, ".defenseclaw-rehome-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(homes) })
	if err := os.Chmod(homes, 0o700); err != nil {
		t.Fatal(err)
	}
	oldHome := filepath.Join(homes, "sample-user-old")
	currentHome := filepath.Join(homes, "sample-user-current")
	for _, home := range []string{oldHome, currentHome} {
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Getuid(), os.Getgid()
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	plugin := func(home string) string {
		return filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	}
	oldPlugin := plugin(oldHome)
	oldReceipt := filepath.Join(oldHome, ".defenseclaw", "connector_backups", "opencode", "config.json")
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "opencode", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "2.1.4",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install old-home OpenCode plugin: %v", err)
	}
	receipt, err := os.ReadFile(oldReceipt)
	if err != nil || !bytes.Contains(receipt, []byte(oldPlugin)) {
		t.Fatalf("old-home receipt does not bind plugin: %v", err)
	}
	var editedBytes []byte
	if edited {
		original, err := os.ReadFile(oldPlugin)
		if err != nil {
			t.Fatal(err)
		}
		editedBytes = append(append([]byte(nil), original...), []byte("\n// operator edit\n")...)
		if err := os.WriteFile(oldPlugin, editedBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	if move {
		if err := os.RemoveAll(oldHome); err != nil {
			t.Fatal(err)
		}
	}
	useEnterpriseHookWorkerHelper(t, "real")
	enterpriseHookWorkerRunner = runEnterpriseHookWorker
	return rehomedOpenCodeCase{
		fixture: f, resolver: resolver,
		entry: enterpriseHookUserCleanup{Connector: "opencode", User: "sample-user", UID: uid,
			UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw"), RecordedAt: time.Now().UTC().Format(time.RFC3339)},
		oldHome: oldHome, currentHome: currentHome, oldPlugin: oldPlugin,
		newPlugin: plugin(currentHome), oldReceipt: oldReceipt, oldEditedBytes: editedBytes,
	}
}

func TestStandaloneCleanupCopiedOpenCodeReceipt(t *testing.T) {
	for _, edited := range []bool{false, true} {
		name := "pristine"
		if edited {
			name = "edited"
		}
		t.Run(name, func(t *testing.T) {
			c := setupRehomedOpenCodeCase(t, edited, false)
			var log bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &log, c.entry, c.resolver)
			if !edited {
				if outcome != enterpriseHookUserCleanupDone || err != nil {
					t.Fatalf("pristine copy cleanup = %v, %v", outcome, err)
				}
				if _, statErr := os.Lstat(c.newPlugin); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("current home still loads the copied plugin: %v", statErr)
				}
				if _, statErr := os.Lstat(c.oldPlugin); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("recorded home still loads the plugin: %v", statErr)
				}
				return
			}
			if outcome != enterpriseHookUserCleanupFailed || err == nil ||
				!strings.Contains(err.Error(), c.oldHome) || !strings.Contains(err.Error(), c.newPlugin) ||
				!strings.Contains(err.Error(), "stale copied receipt") {
				t.Fatalf("edited copy cleanup = %v, %v; want kept row naming the recorded home, the current plugin and the remedy", outcome, err)
			}
			if _, statErr := os.Stat(c.newReceipt()); statErr != nil {
				t.Fatalf("the copied receipt of the kept plugin was lost: %v", statErr)
			}
			if data, readErr := os.ReadFile(c.newPlugin); readErr != nil || !bytes.Equal(data, c.oldEditedBytes) {
				t.Fatalf("unverified current plugin changed: %v", readErr)
			}
			if data, readErr := os.ReadFile(c.oldPlugin); readErr != nil || !bytes.Equal(data, c.oldEditedBytes) {
				t.Fatalf("operator-edited plugin changed: %v", readErr)
			}
			if _, statErr := os.Stat(c.oldReceipt); statErr != nil {
				t.Fatalf("edited plugin's receipt lost: %v", statErr)
			}
		})
	}
}

func TestStandaloneCleanupMovedOpenCodeReceipt(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, true)
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("moved home cleanup = %v, %v", outcome, err)
	}
	if _, err := os.Lstat(c.newPlugin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("moved-home plugin remains: %v", err)
	}
}

// A move by copy, then emptying the old home (rsync and delete), leaves the
// old home as an empty folder. The copied receipt follows the move as it does
// when the old home is gone, so the row ends once the current home is clean
// (GAP-0633).
func TestStandaloneCleanupEmptiedOldHomeOpenCodeReceipt(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, true)
	if err := os.Mkdir(c.oldHome, 0o700); err != nil {
		t.Fatal(err)
	}
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("emptied old home cleanup = %v, %v", outcome, err)
	}
	if _, err := os.Lstat(c.newPlugin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the current home still loads the plugin: %v", err)
	}
}

// A recorded home counts as moved only when it is gone or empty. An rsync
// source that still holds the account's files is a copy: the cleanup runs
// in both homes, ends only when both are clean, leaves the account's own
// files alone, and the audit line says it is a copy, not a move (rel-1-0-3
// GAP-0257).
func TestStandaloneCleanupCallsOnlyAGoneOrEmptyRecordedHomeMoved(t *testing.T) {
	const moved, copied = "the account's home moved from ", "so this is a copy, not a move; per-user cleanup ran in both homes"
	for _, form := range []string{"nonempty source", "emptied source", "source gone"} {
		t.Run(form, func(t *testing.T) {
			c := setupRehomedOpenCodeCase(t, false, form != "nonempty source")
			var own string
			switch form {
			case "nonempty source":
				own = filepath.Join(c.oldHome, "notes.txt")
				if err := os.WriteFile(own, []byte("mine"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "emptied source":
				if err := os.Mkdir(c.oldHome, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			var log bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &log, c.entry, c.resolver)
			if outcome != enterpriseHookUserCleanupDone || err != nil {
				t.Fatalf("cleanup = %v, %v", outcome, err)
			}
			for _, path := range []string{c.newPlugin, c.oldPlugin, c.newReceipt(), c.oldReceipt} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s remains: %v", path, err)
				}
			}
			audit := log.String()
			if form == "nonempty source" {
				if !strings.Contains(audit, "the account's home changed from "+c.oldHome+" to "+c.currentHome) ||
					!strings.Contains(audit, copied) || strings.Contains(audit, moved) {
					t.Fatalf("a nonempty source was not called a copy: %q", audit)
				}
				if data, err := os.ReadFile(own); err != nil || string(data) != "mine" {
					t.Fatalf("the cleanup changed the account's own file in the source: %v", err)
				}
				return
			}
			if !strings.Contains(audit, moved+c.oldHome+" to "+c.currentHome) || strings.Contains(audit, copied) {
				t.Fatalf("a %s was not called moved: %q", form, audit)
			}
		})
	}
}

func (c rehomedOpenCodeCase) newReceipt() string {
	return filepath.Join(c.currentHome, ".defenseclaw", "connector_backups", "opencode", "config.json")
}

// A failed cleanup of a copied home keeps what a retry needs: the edited
// current plugin, its copied receipt and the recorded home's plugin and
// receipt, all byte for byte. The current-home pass acts on the current
// home's copy only; it removed the recorded home's plugin and then the
// copied receipt before (rel-1-0-3 GAP-0200). Once the copy is back to what
// DefenseClaw wrote, the retry removes both plugins and both receipts.
func TestStandaloneCleanupFailedCopiedHomeKeepsBothReceipts(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	pristine, err := os.ReadFile(c.newPlugin)
	if err != nil {
		t.Fatal(err)
	}
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return data
	}
	before := map[string][]byte{c.oldPlugin: read(c.oldPlugin), c.oldReceipt: read(c.oldReceipt), c.newReceipt(): read(c.newReceipt())}
	for attempt := 1; attempt <= 2; attempt++ {
		outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
		if outcome != enterpriseHookUserCleanupFailed || err == nil || !strings.Contains(err.Error(), c.newPlugin) {
			t.Fatalf("attempt %d = %v, %v", attempt, outcome, err)
		}
		if !bytes.Equal(read(c.newPlugin), edited) {
			t.Fatalf("attempt %d changed the edited current plugin", attempt)
		}
		for path, data := range before {
			if !bytes.Equal(read(path), data) {
				t.Fatalf("attempt %d changed %s", attempt, path)
			}
		}
	}
	if err := os.WriteFile(c.newPlugin, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("retry after the copy is pristine = %v, %v", outcome, err)
	}
	for _, path := range []string{c.newPlugin, c.oldPlugin, c.newReceipt(), c.oldReceipt} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains after the clean retry: %v", path, err)
		}
	}
}

func alterCopiedPluginFirstLine(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		t.Fatal("plugin has no first line")
	}
	edited := append([]byte("// operator changed the first line\n"), data[newline+1:]...)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	return edited
}

func TestStandaloneCleanupCopiedOpenCodeChangedMarkerFailsOnRetry(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	for attempt := 1; attempt <= 2; attempt++ {
		outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
		if outcome != enterpriseHookUserCleanupFailed || err == nil ||
			!strings.Contains(err.Error(), c.newPlugin) || !strings.Contains(err.Error(), "remove DefenseClaw's entries") ||
			!strings.Contains(err.Error(), "stale copied receipt") {
			t.Fatalf("attempt %d = %v, %v", attempt, outcome, err)
		}
		if data, err := os.ReadFile(c.newPlugin); err != nil || !bytes.Equal(data, edited) {
			t.Fatalf("attempt %d changed the current plugin: %v", attempt, err)
		}
	}
}

func TestRemoveAllCopiedOpenCodeChangedMarkerKeepsRow(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	now := time.Now()
	if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, now); err != nil {
		t.Fatal(err)
	}
	c.fixture.writeManifest(t)
	manifest, err := enterprisehooks.LoadManifest(c.fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var guardianLog bytes.Buffer
	if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest,
		enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, c.resolver, now); err != nil {
		t.Fatal(err)
	}
	remaining, err := loadEnterpriseHookUserCleanups(c.fixture.dataDir)
	if err != nil || len(remaining) != 1 || !strings.Contains(guardianLog.String(), c.newPlugin) ||
		!strings.Contains(remaining[0].LastError, "rerun") {
		t.Fatalf("guardian row or path warning lost: remaining %+v, %v, log %q", remaining, err, guardianLog.String())
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
	if report.Removed != 0 || len(report.Failed) != 1 || len(report.Pending) != 0 ||
		!strings.Contains(report.Failed[0], c.newPlugin) || !strings.Contains(report.Failed[0], "rerun") ||
		skip[c.entry.UID] != enterpriseHookPurgeSkipFailed {
		t.Fatalf("remove-all did not keep changed copy: report %+v, skip %+v", report, skip)
	}
	if data, err := os.ReadFile(c.newPlugin); err != nil || !bytes.Equal(data, edited) {
		t.Fatalf("remove-all changed current plugin: %v", err)
	}
}

// A manifest row that still names the re-homed account in its current home
// does not hide the pending cleanup of its recorded home: the cleanup runs
// and keeps the row while the copied home still loads a changed plugin
// (GAP-0632).
func TestRemoveAllRunsRehomedCleanupDespiteAManifestRow(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, time.Now()); err != nil {
		t.Fatal(err)
	}
	job := newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: c.entry.UID, GID: os.Getgid(), User: c.entry.User, Home: c.currentHome})
	job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{Mode: enterpriseHookWorkerModeRemove,
		Options: enterpriseHookWorkerOptions{ConnectorName: "opencode"}})
	if enterpriseHookPendingCleanupCoveredByJob(job, "opencode", c.entry, c.resolver) {
		t.Fatal("a manifest row in the current home covered the cleanup of the recorded home")
	}
	same := c.entry
	same.UserHome = c.currentHome
	if !enterpriseHookPendingCleanupCoveredByJob(job, "opencode", same, c.resolver) {
		t.Fatal("a manifest row did not cover the cleanup of the same home")
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	runEnterpriseHookPendingCleanupsWith(cmd, &report, map[int]*enterpriseHookWorkerJob{c.entry.UID: job}, c.resolver)
	if report.Removed != 0 || len(report.Failed) != 1 || !strings.Contains(report.Failed[0], c.newPlugin) {
		t.Fatalf("remove-all skipped the re-homed cleanup: %+v", report)
	}
	if data, err := os.ReadFile(c.newPlugin); err != nil || !bytes.Equal(data, edited) {
		t.Fatalf("remove-all changed the current plugin: %v", err)
	}
}

// A manifest row's removal that leaves a DefenseClaw entry the agent still
// loads is not counted removed (GAP-0632).
func TestRemoveAllReportsRemainingEntries(t *testing.T) {
	job := newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "sample-user", Home: "/home/sample-user"})
	for i, name := range []string{"opencode", "codex"} {
		job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{Index: i, Mode: enterpriseHookWorkerModeRemove,
			Options: enterpriseHookWorkerOptions{ConnectorName: name}})
	}
	run := enterpriseHookWorkerOutcome{Job: *job, Response: enterpriseHookWorkerResponse{Targets: []enterpriseHookWorkerTargetResult{
		{Index: 0, OK: true, PathsReported: true, Remaining: "/home/sample-user/.config/opencode/plugins/defenseclaw.js:1: DefenseClaw connector marker remains in agent config"},
		{Index: 1, OK: true, PathsReported: true},
	}}}
	report := enterpriseHooksRemoveAllReport{}
	addEnterpriseHookRemoveRuns(&report, []enterpriseHookWorkerOutcome{run})
	if report.Removed != 1 || len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "sample-user/opencode: DefenseClaw entries remain") ||
		!strings.Contains(report.Failed[0], "defenseclaw.js:1") || !strings.HasSuffix(report.Failed[0], "and rerun") {
		t.Fatalf("report = %+v", report)
	}
}

func TestStandaloneCleanupCopiedCodexReceiptUsesCurrentConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	oldHome := f.home(t, "sample-codex-old", 0o700)
	currentHome := f.home(t, "sample-codex-current", 0o700)
	uid, gid := os.Getuid(), os.Getgid()
	t.Setenv("HOME", oldHome)
	t.Setenv("CODEX_HOME", "")
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousPath })
	oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "codex-cli 0.142.0",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install Codex in recorded home: %v", err)
	}
	oldReceipt := filepath.Join(oldHome, ".defenseclaw", "connector_backups", "codex", "config.toml.json")
	if data, err := os.ReadFile(oldReceipt); err != nil || !bytes.Contains(data, []byte(oldConfig)) {
		t.Fatalf("Codex receipt does not name the recorded config: %v", err)
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	currentConfig := filepath.Join(currentHome, ".codex", "config.toml")
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	entry := enterpriseHookUserCleanup{Connector: "codex", User: "sample-user", UID: uid,
		UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw")}
	useEnterpriseHookWorkerHelper(t, "real")
	var homes []string
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		homes = append(homes, account.Home)
		return runEnterpriseHookWorker(ctx, account, request)
	}
	// The copy the account edited keeps one changed hook command with the
	// old home's absolute path. Surgical removal must leave that command
	// and name the current config; both homes keep their receipts.
	copied, err := os.ReadFile(currentConfig)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(copied, []byte("codex-hook.sh --event PreToolUse"), []byte("codex-hook.sh --user-edited --event PreToolUse"), 1)
	if bytes.Equal(edited, copied) {
		t.Fatal("the copied config has no PreToolUse hook command to edit")
	}
	if err := os.WriteFile(currentConfig, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupFailed || err == nil || !strings.Contains(err.Error(), currentConfig) ||
		!strings.Contains(err.Error(), "stale copied receipt") || len(homes) != 2 {
		t.Fatalf("edited Codex copy = %v, %v, worker homes %v", outcome, err, homes)
	}
	if data, readErr := os.ReadFile(currentConfig); readErr != nil || !strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
		t.Fatalf("current Codex config unexpectedly cleaned: %v, %q", readErr, data)
	}
	if _, statErr := os.Stat(oldReceipt); statErr != nil {
		t.Fatalf("a failed cleanup lost the recorded home's receipt: %v", statErr)
	}
	if data, readErr := os.ReadFile(oldConfig); readErr != nil || !strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
		t.Fatalf("the current-home pass changed the recorded home's config: %v", readErr)
	}
	// The operator removes the named entries. Only then may the row end,
	// and the recorded home is cleaned by its own receipt.
	if err := os.WriteFile(currentConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err = attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("Codex cleanup after removing entries = %v, %v, worker homes %v", outcome, err, homes)
	}
	if len(homes) != 4 || homes[0] != currentHome || homes[1] != currentHome || homes[2] != currentHome || homes[3] != oldHome {
		t.Fatalf("cleanup used unexpected homes: %v", homes)
	}
	for _, path := range []string{currentConfig, oldConfig} {
		data, err := os.ReadFile(path)
		if err != nil || strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
			t.Fatalf("Codex config %s still has DefenseClaw entries: %v, %q", path, err, data)
		}
	}
}

// A copy left as DefenseClaw wrote it is restored from its own copied
// receipt: one pass per home ends the row.
func TestStandaloneCleanupPristineCodexCopyEndsInOnePass(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	oldHome := f.home(t, "sample-codex-old", 0o700)
	currentHome := f.home(t, "sample-codex-current", 0o700)
	uid, gid := os.Getuid(), os.Getgid()
	t.Setenv("HOME", oldHome)
	t.Setenv("CODEX_HOME", "")
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousPath })
	oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "codex-cli 0.142.0",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install Codex in recorded home: %v", err)
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	currentConfig := filepath.Join(currentHome, ".codex", "config.toml")
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	entry := enterpriseHookUserCleanup{Connector: "codex", User: "sample-user", UID: uid,
		UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw")}
	useEnterpriseHookWorkerHelper(t, "real")
	enterpriseHookWorkerRunner = runEnterpriseHookWorker
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("pristine Codex copy = %v, %v", outcome, err)
	}
	for _, path := range []string{currentConfig, oldConfig} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "model = \"gpt-5\"\n" {
			t.Fatalf("Codex config %s was not restored exactly: %v, %q", path, err, data)
		}
	}
}

// A manifest row that carries its own uid, gid and home names the recorded
// home of an account the directory has re-homed to a copy. remove-all runs
// the row as a re-homed cleanup: while the copied current home loads a
// changed plugin, the row is Failed with that path and the remedy, it is not
// counted removed, and the account's state is not purged. Once both homes
// are clean the row is removed (GAP-0073).
func TestRemoveAllRehomedManifestRowChecksTheCurrentHome(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	pristine, err := os.ReadFile(c.newPlugin)
	if err != nil {
		t.Fatal(err)
	}
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	uid, gid := c.entry.UID, os.Getgid()
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		User: "sample-user", UserHome: c.oldHome, UID: &uid, GID: &gid,
		Connector: "opencode", DataDir: filepath.Join(c.oldHome, ".defenseclaw"),
	}}}
	removeAll := func() (enterpriseHooksRemoveAllReport, map[int]string, []string) {
		rows := resolveEnterpriseHookRemoveRows(manifest)
		jobs, pending, failed := enterpriseHookRemoveJobs(rows)
		if len(pending) != 0 || len(failed) != 0 {
			t.Fatalf("rows = pending %v, failed %v", pending, failed)
		}
		if job := jobs[uid]; job != nil && enterpriseHookJobRemoves(job, "opencode") {
			t.Fatal("the re-homed row was removed in its recorded home only")
		}
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		report := enterpriseHooksRemoveAllReport{}
		skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs, enterpriseHookRehomedRowCleanups(rows)...)
		return report, skip, addEnterpriseHookStatePurges(jobs, rows, skip)
	}
	report, skip, notPurged := removeAll()
	if report.Removed != 0 || len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "sample-user/opencode: ") ||
		!strings.Contains(report.Failed[0], c.newPlugin) || !strings.Contains(report.Failed[0], "stale copied receipt") ||
		!strings.Contains(report.Failed[0], "rerun") || skip[uid] != enterpriseHookPurgeSkipFailed {
		t.Fatalf("copied home with a changed plugin counted removed: report %+v, skip %+v", report, skip)
	}
	if len(notPurged) != 1 || notPurged[0] != "sample-user: "+enterpriseHookPurgeSkipFailed {
		t.Fatalf("not purged = %v", notPurged)
	}
	if data, err := os.ReadFile(c.newPlugin); err != nil || !bytes.Equal(data, edited) {
		t.Fatalf("remove-all changed the current plugin: %v", err)
	}
	// The operator puts back DefenseClaw's own plugin; now both homes clean.
	if err := os.WriteFile(c.newPlugin, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	report, skip, notPurged = removeAll()
	if report.Removed != 1 || len(report.Failed) != 0 || len(report.Pending) != 0 || skip[uid] != enterpriseHookPurgeSkipRehomed {
		t.Fatalf("clean homes = report %+v, skip %+v", report, skip)
	}
	if len(notPurged) != 1 || notPurged[0] != "sample-user: "+enterpriseHookPurgeSkipRehomed {
		t.Fatalf("not purged = %v", notPurged)
	}
	for _, plugin := range []string{c.newPlugin, c.oldPlugin} {
		if _, err := os.Lstat(plugin); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still loads: %v", plugin, err)
		}
	}
}

// A row with its own uid, gid and home whose account the directory gives
// the same home, gives no home, or does not know is removed in that home, as
// before.
func TestRemoveAllExplicitRowKeepsItsHomeUnlessRehomed(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"same-user":   {Name: "same-user", UID: 5101, GID: 5101, Home: "/home/same-user"},
		"nohome-user": {Name: "nohome-user", UID: 5102, GID: 5102, Home: "/var/empty"},
		"renamed":     {Name: "renamed", UID: 5103, GID: 5103, Home: "/home/renamed"},
	}}
	for _, tc := range []struct {
		user string
		uid  int
		home string
	}{
		{"same-user", 5101, "/home/same-user"},
		{"nohome-user", 5102, "/home/nohome-user"},
		{"old-name", 5103, "/home/old-name"},
		{"unknown", 5104, "/home/unknown"},
	} {
		uid := tc.uid
		target := enterprisehooks.ManifestTarget{User: tc.user, UserHome: tc.home, UID: &uid, GID: &uid, Connector: "opencode"}
		if current, name := enterpriseHookRemoveRowDirectoryHome(target, resolver); current != "" || name != "" {
			t.Errorf("%s: re-homed to %q (%q)", tc.user, current, name)
		}
	}
	resolver.accounts["moved"] = unixidentity.Account{Name: "moved", UID: 5105, GID: 5105, Home: "/home/moved-new"}
	uid := 5105
	for _, user := range []string{"moved", ""} {
		target := enterprisehooks.ManifestTarget{User: user, UserHome: "/home/moved", UID: &uid, GID: &uid, Connector: "opencode"}
		if current, name := enterpriseHookRemoveRowDirectoryHome(target, resolver); current != "/home/moved-new" || name != "moved" {
			t.Errorf("user %q: re-homed = %q, %q", user, current, name)
		}
	}
}
