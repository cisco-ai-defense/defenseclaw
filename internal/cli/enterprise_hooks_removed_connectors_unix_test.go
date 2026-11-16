//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// until 1.1 (GAP-1845): a managed Linux/macOS account a 1.0.4 standalone
// guardian set up for OpenHands and OmniGent. The guardian's next apply job
// for the account (the package upgrade, the verify timer, uninstall) removes
// what DefenseClaw wrote for them and keeps the account's own entries; the
// job never fails on it, and the Secure Client guardian leaves it alone.
func TestManagedUnixGuardianJobRemovesWhatDefenseClawWroteForRemovedConnectors(t *testing.T) {
	for _, standalone := range []bool{true, false} {
		t.Run("standalone="+strconv.FormatBool(standalone), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("OMNIGENT_CONFIG", "")
			t.Setenv("OMNIGENT_CONFIG_HOME", "")
			dataDir := filepath.Join(home, ".defenseclaw")
			script := filepath.Join(dataDir, "hooks", "openhands-hook.sh")
			module := filepath.Join(dataDir, "hooks", "defenseclaw_omnigent_policy.py")
			hooksJSON := filepath.Join(home, ".openhands", "hooks.json")
			omniConfig := filepath.Join(home, ".omnigent", "config.yaml")
			files := map[string]string{
				script: "#!/bin/sh -p\n# defenseclaw-managed-hook v0 (disabled tombstone)\nexit 2\n",
				module: "# defenseclaw-managed-policy v0 (disabled tombstone)\nraise SystemExit(2)\n",
				hooksJSON: `{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":` + strconv.Quote(script) +
					`},{"type":"command","command":"/opt/mine/hook"}]}]}`,
				omniConfig: "policy_modules:\n  - operator_own_policy\n  - defenseclaw_omnigent_policy\nmodel: m\n",
			}
			for path, body := range files {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previousVerifier, previousLog := enterpriseHookWorkerVerifier, enterpriseHookWorkerRemovedLog
			t.Cleanup(func() { enterpriseHookWorkerVerifier, enterpriseHookWorkerRemovedLog = previousVerifier, previousLog })
			enterpriseHookWorkerVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
				return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
			}
			var log bytes.Buffer
			enterpriseHookWorkerRemovedLog = &log
			request := enterpriseHookWorkerRequest{
				Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: standalone,
				Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeVerify, Options: enterpriseHookWorkerOptions{
					ConnectorName: "codex", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir,
				}}},
			}
			results := runEnterpriseHookWorkerApply(context.Background(), request).Targets
			if len(results) != 1 || !results[0].OK {
				t.Fatalf("the job failed: %+v", results)
			}
			hooks, _ := os.ReadFile(hooksJSON)
			omni, _ := os.ReadFile(omniConfig)
			_, scriptErr := os.Lstat(script)
			_, moduleErr := os.Lstat(module)
			if !standalone {
				if !strings.Contains(string(hooks), "openhands-hook.sh") || scriptErr != nil || log.Len() != 0 {
					t.Fatalf("the Secure Client guardian changed the account: hooks.json=%s log=%q", hooks, log.String())
				}
				return
			}
			if strings.Contains(string(hooks), "openhands-hook.sh") || !strings.Contains(string(hooks), "/opt/mine/hook") {
				t.Errorf("hooks.json after the job:\n%s", hooks)
			}
			if strings.Contains(string(omni), "defenseclaw_omnigent_policy") || !strings.Contains(string(omni), "operator_own_policy") {
				t.Errorf("config.yaml after the job:\n%s", omni)
			}
			if scriptErr == nil || moduleErr == nil {
				t.Errorf("a deny stub is still there: script=%v module=%v", scriptErr, moduleErr)
			}
			if got := strings.Count(log.String(), connector.RemovedConnectorNotice); got != 1 {
				t.Errorf("the notice was logged %d times:\n%s", got, log.String())
			}
		})
	}
}

// stageRemovedConnectorAccount writes what a 1.0.4 standalone guardian left
// in an account for OpenHands and OmniGent: both deny stubs, DefenseClaw's
// registrations next to the account's own, and a copy 1.0.4 saved of an
// edited module, which the teardown keeps by design.
func stageRemovedConnectorAccount(t *testing.T) (home, dataDir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OMNIGENT_CONFIG", "")
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	dataDir = filepath.Join(home, ".defenseclaw")
	script := filepath.Join(dataDir, "hooks", "openhands-hook.sh")
	files := map[string]string{
		script: "#!/bin/sh -p\n# defenseclaw-managed-hook v0 (disabled tombstone)\nexit 2\n",
		filepath.Join(dataDir, "hooks", "defenseclaw_omnigent_policy.py"): "# defenseclaw-managed-policy v0 (disabled tombstone)\nraise SystemExit(2)\n",
		filepath.Join(home, ".openhands", "hooks.json"): `{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":` + strconv.Quote(script) +
			`},{"type":"command","command":"/opt/mine/hook"}]}]}`,
		filepath.Join(home, ".omnigent", "config.yaml"):                              "policy_modules:\n  - operator_own_policy\n  - defenseclaw_omnigent_policy\nmodel: m\n",
		filepath.Join(dataDir, "connector_backups", "omnigent", ".edited-policy.py"): "# the user's edit\n",
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, dataDir
}

func requireRemovedConnectorStubsGone(t *testing.T, dataDir string) {
	t.Helper()
	for _, name := range []string{"openhands-hook.sh", "defenseclaw_omnigent_policy.py"} {
		if _, err := os.Lstat(filepath.Join(dataDir, "hooks", name)); err == nil {
			t.Errorf("the %s deny stub is still there", name)
		}
	}
}

// A 1.0.3 manifest row for OmniGent or OpenHands that 1.0.5 dropped becomes
// a per-user cleanup (Remove) and, at uninstall, a Purge of the account. The
// job's removed-connector teardown already removed what DefenseClaw wrote, so
// the Remove is done without the registry (which no longer resolves the name)
// and the Purge of the same account runs (GAP-1915).
func TestManagedUnixGuardianRemoveOfADroppedRemovedConnectorRowIsDoneAndThePurgeRuns(t *testing.T) {
	home, dataDir := stageRemovedConnectorAccount(t)
	previousPurger, previousStop, previousLog := enterpriseHookWorkerPurger, enterpriseHookWorkerStopPerUser, enterpriseHookWorkerRemovedLog
	t.Cleanup(func() {
		enterpriseHookWorkerPurger, enterpriseHookWorkerStopPerUser, enterpriseHookWorkerRemovedLog = previousPurger, previousStop, previousLog
	})
	enterpriseHookWorkerRemovedLog = io.Discard
	enterpriseHookWorkerStopPerUser = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	purged := 0
	enterpriseHookWorkerPurger = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.PurgeSummary, error) {
		purged++
		return enterprisehooks.PurgeSummary{}, nil
	}
	options := func(name string) enterpriseHookWorkerOptions {
		return enterpriseHookWorkerOptions{ConnectorName: name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir}
	}
	request := enterpriseHookWorkerRequest{
		Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: true,
		Targets: []enterpriseHookWorkerTarget{
			{Index: 0, Mode: enterpriseHookWorkerModeRemove, Options: options("omnigent")},
			{Index: 1, Mode: enterpriseHookWorkerModeRemoveLeftover, Options: options("openhands")},
			{Index: 2, Mode: enterpriseHookWorkerModePurge, Options: options("omnigent")},
		},
	}
	results := runEnterpriseHookWorkerApply(context.Background(), request).Targets
	if len(results) != 3 {
		t.Fatalf("results = %+v", results)
	}
	for _, result := range results {
		if !result.OK || result.Error != "" {
			t.Errorf("target %d failed: %+v", result.Index, result)
		}
	}
	if !results[0].PathsReported {
		t.Errorf("the Remove reports no paths, so the cleanup is never done: %+v", results[0])
	}
	if purged != 1 {
		t.Errorf("the purge ran %d times, want 1", purged)
	}
	requireRemovedConnectorStubsGone(t, dataDir)
}

// An account whose row is gone and that has no other per-user target still
// had the 1.0.4 deny stubs. The guardian starts its foreign-cleanup job for
// it (the stubs are there) and the job, with no target, tears them down in
// the account's default data folder (GAP-1916).
func TestManagedUnixGuardianAccountWithNoTargetIsTornDown(t *testing.T) {
	home, dataDir := stageRemovedConnectorAccount(t)
	previousLog := enterpriseHookWorkerRemovedLog
	t.Cleanup(func() { enterpriseHookWorkerRemovedLog = previousLog })
	enterpriseHookWorkerRemovedLog = io.Discard
	if !accountHasRemovedConnectorFiles(home) {
		t.Fatal("the guardian sees no work for an account with the deny stubs")
	}
	removeRetiredConnectorsForAccount(context.Background(), enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: true})
	requireRemovedConnectorStubsGone(t, dataDir)
	if accountHasRemovedConnectorFiles(home) {
		t.Error("the guardian still sees work after the teardown")
	}
	hooks, _ := os.ReadFile(filepath.Join(home, ".openhands", "hooks.json"))
	if strings.Contains(string(hooks), "openhands-hook.sh") || !strings.Contains(string(hooks), "/opt/mine/hook") {
		t.Errorf("hooks.json after the job:\n%s", hooks)
	}
}

// A leftover the teardown keeps by design (the copy 1.0.4 saved of an edited
// module) is logged under the notice once, by the job that removed the rest;
// later jobs of the account log nothing again (GAP-1917).
func TestManagedUnixGuardianLogsTheRemovalNoticeOnce(t *testing.T) {
	home, dataDir := stageRemovedConnectorAccount(t)
	previousLog := enterpriseHookWorkerRemovedLog
	t.Cleanup(func() { enterpriseHookWorkerRemovedLog = previousLog })
	request := enterpriseHookWorkerRequest{
		Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: true,
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptions{
			ConnectorName: "omnigent", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir,
		}}},
	}
	for job := 1; job <= 3; job++ {
		var log bytes.Buffer
		enterpriseHookWorkerRemovedLog = &log
		runEnterpriseHookWorkerApply(context.Background(), request)
		want := 0
		if job == 1 {
			want = 1
		}
		if got := strings.Count(log.String(), connector.RemovedConnectorNotice); got != want {
			t.Errorf("job %d logged the notice %d times, want %d:\n%s", job, got, want, log.String())
		}
		if job > 1 && log.Len() != 0 {
			t.Errorf("job %d logged again:\n%s", job, log.String())
		}
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "connector_backups", "omnigent", ".edited-policy.py")); err != nil {
		t.Fatalf("the saved copy went: %v", err)
	}
}

// Only the copy the teardown keeps by design is left (the state a 1.0.4
// upgrade of an edited OmniGent module leaves). The first job logs it under
// the notice; later jobs log nothing again; a new leftover is logged
// (GAP-2016, GAP-1917).
func TestManagedUnixGuardianLogsAKeptCopyOnTheFirstJobOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OMNIGENT_CONFIG", "")
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	dataDir := filepath.Join(home, ".defenseclaw")
	saved := filepath.Join(dataDir, "connector_backups", "omnigent", "defenseclaw_omnigent_policy.py.edited-ae793da7fbcd2b16")
	if err := os.MkdirAll(filepath.Dir(saved), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, []byte("# the user's edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousLog := enterpriseHookWorkerRemovedLog
	t.Cleanup(func() { enterpriseHookWorkerRemovedLog = previousLog })
	request := enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: true}
	for job, want := range []int{1, 0, 0} {
		var log bytes.Buffer
		enterpriseHookWorkerRemovedLog = &log
		removeRetiredConnectorsForAccount(context.Background(), request)
		if got := strings.Count(log.String(), connector.RemovedConnectorNotice); got != want {
			t.Errorf("job %d logged the notice %d times, want %d:\n%s", job+1, got, want, log.String())
		}
		if want == 1 && !strings.Contains(log.String(), filepath.Dir(saved)+": files DefenseClaw saved") {
			t.Errorf("job %d does not name the kept copy:\n%s", job+1, log.String())
		}
		if want == 0 && log.Len() != 0 {
			t.Errorf("job %d logged again:\n%s", job+1, log.String())
		}
	}
	if data, err := os.ReadFile(saved); err != nil || string(data) != "# the user's edit\n" {
		t.Fatalf("the saved copy changed: %q %v", data, err)
	}
	token := filepath.Join(dataDir, "hooks", ".hookcfg.openhands")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "elsewhere"), token); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	enterpriseHookWorkerRemovedLog = &log
	removeRetiredConnectorsForAccount(context.Background(), request)
	if !strings.Contains(log.String(), token) {
		t.Errorf("a new leftover is not logged:\n%s", log.String())
	}
}

// GAP-2504: a managed macOS pkg upgrade from 1.0.3 with OmniGent and
// OpenHands rows enrolled failed its first run. Until the 1.0.5 enumerator
// rewrote the manifest, the guardian verified those rows with a registry
// that no longer has them; the real worker fails each with "unknown
// connector", and the postinstall failed on guardian_target_failed. The
// rows are not enrolled targets: no install or verify target is sent for
// them, the pass fails nothing, and the other rows are reconciled as usual.
func TestManagedUnixGuardianPassSkipsTheRowsOfRemovedConnectors(t *testing.T) {
	accounts := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, accounts)
	alice, bob := f.home(t, "alice", 0o700), f.home(t, "bob", 0o700)
	accounts.accounts["alice"] = unixidentity.Account{Name: "alice", UID: 5001, GID: 5001, Home: alice, Shell: "/bin/bash"}
	accounts.accounts["bob"] = unixidentity.Account{Name: "bob", UID: 5002, GID: 5002, Home: bob, Shell: "/bin/bash"}
	previousCheck, previousSet := enterpriseHookCheckHome, enterpriseHookStandaloneMachinePolicySet
	t.Cleanup(func() { enterpriseHookCheckHome, enterpriseHookStandaloneMachinePolicySet = previousCheck, previousSet })
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return map[string]struct{}{} }
	runner := enterpriseHookWorkerRunner
	var sent []string
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := runner(ctx, account, request)
		for i, target := range request.Targets {
			name := target.Options.ConnectorName
			sent = append(sent, name+"@"+target.Mode)
			if connector.IsRemovedConnector(name) && target.Mode != enterpriseHookWorkerModeRemove && target.Mode != enterpriseHookWorkerModeRemoveLeftover {
				// What the real worker answers: the registry no longer
				// resolves the name.
				response.Targets[i] = enterpriseHookWorkerTargetResult{Index: target.Index, Error: "enterprise hooks: unknown connector \"" + name + "\""}
			}
		}
		return response, err
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "omnigent"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "openhands"},
	)
	f.writeLedger(t, protectedRow("alice", alice, "hermes"), protectedRow("alice", alice, "omnigent"), protectedRow("bob", bob, "openhands"))
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.Failures != 0 {
		t.Errorf("the pass failed %d targets; rows = %+v", run.Failures, run.Rows)
	}
	for _, row := range run.Rows {
		if connector.IsRemovedConnector(row.Connector) {
			t.Errorf("the pass reconciled a removed connector row: %+v", row)
		}
	}
	for _, target := range run.Targets {
		if connector.IsRemovedConnector(target.Connector) {
			t.Errorf("the pass counts a removed connector row as enrolled: %+v", target)
		}
	}
	hermes := false
	for _, entry := range sent {
		name, mode, _ := strings.Cut(entry, "@")
		if connector.IsRemovedConnector(name) && mode != enterpriseHookWorkerModeRemove && mode != enterpriseHookWorkerModeRemoveLeftover {
			t.Errorf("the pass sent %s as an enrolled target", entry)
		}
		hermes = hermes || entry == "hermes@"+enterpriseHookWorkerModeVerifyOrRepair
	}
	if !hermes {
		t.Errorf("alice hermes was not reconciled; sent %v", sent)
	}
}
