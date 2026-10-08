// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// observingRunner calls observe before every command it passes on.
type observingRunner struct {
	Runner
	observe func(name string, args []string)
}

func (r observingRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	r.observe(name, args)
	return r.Runner.Run(ctx, name, args...)
}

// observingPolicy calls observe before removing machine policy.
type observingPolicy struct {
	MachinePolicyManager
	observe func()
}

func (p observingPolicy) RemoveAll() (enterprisepolicy.Result, error) {
	p.observe()
	return p.MachinePolicyManager.RemoveAll()
}

// The guardian repairs any DefenseClaw registration that disappears from a
// manifest target within about a second. Uninstall must stop it, the
// enumerator and the lifecycle triggers before it removes the per-user and
// machine-policy registrations, or the guardian puts them back and they
// outlive the binary they name. The gateway keeps answering until then.
func TestUninstallStopsRepairersBeforeRemovingRegistrations(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			gateway := unitGateway
			if goos == "darwin" {
				gateway = labelGateway
			}
			var problems []string
			check := func(step string) {
				for _, unit := range h.services.Units() {
					if repairsRegistrations(unit) && h.services.isActive(unit.Name) {
						problems = append(problems, step+": "+unit.Name+" still running")
					}
				}
				if !h.services.isActive(gateway) {
					problems = append(problems, step+": the gateway was already stopped")
				}
			}
			removeAll := false
			h.env.Runner = observingRunner{Runner: h.runner, observe: func(name string, args []string) {
				if strings.Contains(strings.Join(args, " "), "hooks remove-all") {
					removeAll = true
					check("per-user remove-all")
				}
			}}
			policyRemoved := false
			h.env.MachinePolicy = observingPolicy{MachinePolicyManager: h.env.MachinePolicy, observe: func() {
				policyRemoved = true
				check("machine policy removal")
			}}
			before := len(h.services.calls)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			// GAP-1443: a macOS disable writes a launchd override that no
			// command deletes; the definitions are removed instead.
			for _, call := range h.services.calls[before:] {
				if goos == "darwin" && strings.HasPrefix(call, "disable ") {
					t.Fatalf("uninstall ran %q, which leaves a launchd override", call)
				}
			}
			if !removeAll || !policyRemoved {
				t.Fatalf("uninstall skipped a registration removal: per-user=%v machine-policy=%v", removeAll, policyRemoved)
			}
			if len(problems) > 0 {
				t.Fatalf("registrations were removed while they could be repaired:\n%s", strings.Join(problems, "\n"))
			}
			for _, unit := range h.services.Units() {
				if h.services.isActive(unit.Name) {
					t.Fatalf("%s still running after uninstall", unit.Name)
				}
				// A removed launchd label goes back to launchd's default,
				// enabled, instead of staying listed as disabled (MAC-R1-23).
				if unit.Activate && h.services.enabled[unit.Name] != (goos == "darwin") {
					t.Fatalf("%s enabled=%v after uninstall", unit.Name, h.services.enabled[unit.Name])
				}
			}
		})
	}
}

// An uninstall that cannot remove one file keeps the deployment record, so
// rerunning uninstall finishes the removal and a reinstall through ensure
// (the package postinstall, an MDM run) restores the deployment without
// --adopt-existing. Before, the record was deleted first: the rerun was a
// not_installed no-op and the reinstall refused the leftovers.
func TestFailedUninstallKeepsTheRecordForARetryOrReinstall(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove files from a read-only directory")
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			configDir := h.env.P(h.env.Layout.ConfigDir)
			lock := func() {
				if err := os.Chmod(configDir, 0o555); err != nil {
					t.Fatal(err)
				}
			}
			unlock := func() {
				if err := os.Chmod(configDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = os.Chmod(configDir, 0o755) })
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))

			// The runtime descriptor in the config directory cannot be removed.
			lock()
			failed := h.run(Options{Action: ActionUninstall})
			unlock()
			requireError(t, failed, codeUninstall)
			if record, err := h.env.loadDeployment(); err != nil || record == nil {
				t.Fatalf("a failed uninstall removed the deployment record (%v)", err)
			}
			// The package postinstall or an MDM run reinstalls through ensure.
			requireOK(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.0")}))

			// A rerun of a failed uninstall finishes the removal.
			lock()
			requireError(t, h.run(Options{Action: ActionUninstall}), codeUninstall)
			unlock()
			retry := h.run(Options{Action: ActionUninstall})
			requireOK(t, retry)
			if retry.Noop {
				t.Fatal("the rerun of a failed uninstall was a no-op")
			}
			if exists(h.env.P(h.env.Layout.DescriptorPath)) || exists(h.env.deploymentPath()) {
				t.Fatal("the rerun did not finish the removal")
			}
		})
	}
}

// failingRemoveAccounts cannot delete the service account.
type failingRemoveAccounts struct{ AccountManager }

func (failingRemoveAccounts) Remove(context.Context, string) error {
	return errors.New("remove /Users/_defenseclaw: eDSPermissionError")
}

// macOS can deny the directory-record delete of the service account (GAP-0101).
// The uninstall had already removed the binaries, the CLI included, so
// failing it left a command that could not be rerun. It completes and tells
// the administrator how to delete the account.
func TestUninstallCompletesWhenTheServiceAccountCannotBeDeleted(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Accounts = failingRemoveAccounts{h.env.Accounts}
	done := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, done)
	if len(done.Warnings) != 1 || done.Warnings[0].Code != codeAccount ||
		!strings.Contains(done.Warnings[0].Message, "sudo dscl . -delete /Users/"+h.env.Layout.ServiceUser) {
		t.Fatalf("warnings = %+v, want the service-account warning with the delete command", done.Warnings)
	}
	if exists(h.env.deploymentPath()) {
		t.Fatal("the deployment record is still there: the uninstall did not complete")
	}
}

// removeAllRunner answers `enterprise hooks remove-all` with answer.
type removeAllRunner struct {
	Runner
	answer func(args string) (CommandResult, error)
}

func (r removeAllRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if joined := strings.Join(args, " "); strings.HasPrefix(joined, "enterprise hooks remove-all ") {
		return r.answer(joined)
	}
	return r.Runner.Run(ctx, name, args...)
}

// A macOS uninstall --purge returned ok while one account's Devin hooks,
// which run the hook binary that same uninstall removed, stayed registered,
// and its only warning named nobody. Each registration left is now an
// error naming the account and connector with the command to rerun, and
// the uninstall stops before removing the binaries they run, so the rerun
// can still remove them.
func TestUninstallKeepsTheBinariesWhilePerUserHooksRemain(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			left := true
			var calls []string
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(args string) (CommandResult, error) {
				calls = append(calls, args)
				if left {
					return CommandResult{ExitCode: 1, Stdout: []byte(`{"ok":false,"removed":2,"failed":["alice/devin: devin teardown: remove hook entries: permission denied"]}`)}, errors.New("exit 1")
				}
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":1,"purged":["alice"]}`)}, nil
			}}
			failed := h.run(Options{Action: ActionUninstall, Purge: true})
			requireError(t, failed, codePerUserHooks)
			got := messagesOf(failed.Errors, codePerUserHooks)
			if !strings.Contains(got, "devin hooks for user alice were not removed: devin teardown: remove hook entries: permission denied") ||
				!strings.Contains(got, h.env.lifecycleCommand(ActionUninstall)+" --purge`") {
				t.Fatalf("the uninstall does not name the registration left and the rerun: %s", got)
			}
			if len(calls) != 1 || !strings.HasSuffix(calls[0], " --purge") {
				t.Fatalf("a purge does not purge per-user state: %v", calls)
			}
			gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
			if !exists(gateway) || !exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall removed the binaries the registration left still runs")
			}
			left = false
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			if exists(gateway) || exists(h.env.deploymentPath()) {
				t.Fatal("the rerun did not finish the removal")
			}
			// MAC-R1-22: the purge names the accounts whose data it deleted.
			if !strings.Contains(strings.Join(done.Changes, "\n"), "per-user data of user alice") {
				t.Fatalf("the purge does not report the per-user data it removed: %v", done.Changes)
			}
			// The purge removes everything, the hook scripts included, and
			// says so (it ran only after every registration went).
			if changes := strings.Join(done.Changes, "\n"); !strings.Contains(changes, "including its hook scripts") ||
				!strings.Contains(changes, "per-user binaries") || strings.Contains(changes, "except ~/.defenseclaw/hooks") {
				t.Fatalf("the purge report does not say it removed everything: %v", done.Changes)
			}
		})
	}
}

// GAP-1444: uninstall --purge said every enrolled account lost per-user
// binaries and a per-user gateway, also an account that never had a
// per-user install. Each account's line now names only what was removed.
func TestUninstallPurgeNamesOnlyWhatEachAccountHad(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"purged":["alice","bob"],` +
			`"purged_detail":{"alice":{"data":true},"bob":{"data":true,"binaries":true,"gateway":true}}}`)}, nil
	}}
	done := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, done)
	lines := map[string]string{}
	for _, change := range done.Changes {
		for _, user := range []string{"alice", "bob"} {
			if strings.Contains(change, "of user "+user+" ") {
				lines[user] = change
			}
		}
	}
	if alice := lines["alice"]; !strings.Contains(alice, "~/.defenseclaw") ||
		strings.Contains(alice, "~/.local/bin") || strings.Contains(alice, "gateway") {
		t.Fatalf("alice had only ~/.defenseclaw: %q", alice)
	}
	if bob := lines["bob"]; !strings.Contains(bob, "launcher links in ~/.local/bin") ||
		!strings.HasSuffix(bob, "after stopping its per-user gateway") {
		t.Fatalf("bob had a full per-user install: %q", bob)
	}
	if got := purgedUserChange("carol", &purgedUserDetail{}); got != "found no DefenseClaw per-user data or binaries of user carol to remove" {
		t.Fatalf("an account with nothing to remove: %q", got)
	}
	// GAP-1947: the uv cache entries the purge removed are named too.
	if got := purgedUserChange("dave", &purgedUserDetail{Data: true, UVCache: true}); !strings.Contains(got, "~/.defenseclaw") ||
		!strings.HasSuffix(got, "and DefenseClaw's entries in its uv cache (~/.cache/uv)") {
		t.Fatalf("an account with uv cache entries: %q", got)
	}
	if got := purgedUserChange("erin", &purgedUserDetail{UVCache: true}); got != "removed DefenseClaw's entries in the uv cache (~/.cache/uv) of user erin" {
		t.Fatalf("an account with only uv cache entries: %q", got)
	}
}

// packageOwnedRunner answers the host commands a purge without a deployment
// record runs: rpm owns the gateway, and getent lists passwd.
type packageOwnedRunner struct {
	Runner
	passwd string
}

func (r packageOwnedRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	switch {
	case name == "rpm":
		return CommandResult{}, nil
	case name == "getent" && len(args) == 1 && args[0] == "passwd":
		return CommandResult{Stdout: []byte(r.passwd)}, nil
	}
	return r.Runner.Run(ctx, name, args...)
}

// GAP-2632: after a default uninstall of the rpm, the purge that uninstall
// named reported done, removed no account's ~/.defenseclaw, named nobody and
// deleted the rpm's binaries. The default uninstall removes the enrollment
// record a purge needs, so it now names a step that works, and a purge
// without the record keeps the package's files and names each account whose
// files stay.
func TestPurgeAfterDefaultUninstallNamesTheAccountsItCannotClean(t *testing.T) {
	h := packageHost(t, "1.0.0")
	h.env.Runner = packageOwnedRunner{Runner: h.runner, passwd: "root:x:0:0:root:/root:/bin/bash\n" +
		"alice:x:1001:1001::/home/alice:/bin/bash\nbob:x:1002:1002::/home/bob:/bin/bash\n"}
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		`{"accounts":[{"user":"alice","home":"/home/alice"},{"user":"bob","home":"/home/bob"}]}`)
	writeHostFile(t, h, "/home/alice/.defenseclaw/hook_contract_lock.json", "{}")

	plain := h.run(Options{Action: ActionUninstall})
	requireOK(t, plain)
	kept := strings.Join(plain.Changes, "\n")
	if !strings.Contains(kept, "kept: the DefenseClaw per-user data (~/.defenseclaw) of alice.") ||
		!strings.Contains(kept, "activate the deployment again with `"+h.env.lifecycleCommand(ActionEnsure)+" --from-package --config <file>` and run `") ||
		strings.Contains(kept, "while the defenseclaw-enterprise package is installed") {
		t.Fatalf("the default uninstall names a purge that cannot find the accounts:\n%s", kept)
	}

	purge := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, purge)
	got := messagesOf(purge.Warnings, codePerUserState)
	if !strings.Contains(got, "not removed: the DefenseClaw per-user data (~/.defenseclaw) of alice.") ||
		strings.Contains(got, "bob") || !strings.Contains(got, "--from-package --config <file>`") {
		t.Fatalf("the purge does not name the account whose data stays: %q", got)
	}
	if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) {
		t.Fatal("the purge removed the binaries the rpm still owns")
	}
	// The rpm ships the managed OpenCode plugin too (GAP-0763).
	if !exists(h.env.P(enterprisepolicy.OpenCodeManagedPluginPath(h.env.Layout))) {
		t.Fatal("the uninstall removed the OpenCode plugin the rpm still owns")
	}
	if !exists(h.env.P("/home/alice/.defenseclaw")) {
		t.Fatal("the purge deleted a home folder without an enrollment record")
	}
}

// A purge after --keep-state still has the enrollment record and the config,
// so it purges the enrolled accounts, which its kept line said it would.
func TestPurgeAfterKeepStateUninstallPurgesTheAccounts(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets: []\n")
	requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
	var calls []string
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(args string) (CommandResult, error) {
		calls = append(calls, args)
		return CommandResult{Stdout: []byte(`{"ok":true,"purged":["alice"],"purged_detail":{"alice":{"data":true}}}`)}, nil
	}}
	purge := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, purge)
	if len(calls) != 1 || !strings.HasSuffix(calls[0], " --purge") {
		t.Fatalf("the purge did not purge the enrolled accounts: %v", calls)
	}
	if !strings.Contains(strings.Join(purge.Changes, "\n"), "per-user data of user alice") {
		t.Fatalf("the purge does not name the account it purged: %v", purge.Changes)
	}
}

// GAP-0516: a plain uninstall that removes the service account but leaves
// the package installed turns off the package's tmpfiles.d entries, which
// name that account; the next install removes the override.
func TestPackageKeptUninstallTurnsOffTheTmpfilesEntriesUntilTheNextInstall(t *testing.T) {
	h := packageHost(t, "1.0.0")
	h.env.Runner = packageOwnedRunner{Runner: h.runner, passwd: "root:x:0:0:root:/root:/bin/bash\n"}
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if got := h.read(packageTmpfilesOverride); !strings.HasPrefix(got, packageTmpfilesOverrideMarker) {
		t.Fatalf("no tmpfiles.d override after the uninstall: %q", got)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	if exists(h.env.P(packageTmpfilesOverride)) {
		t.Fatal("the next install kept the tmpfiles.d override")
	}
}
