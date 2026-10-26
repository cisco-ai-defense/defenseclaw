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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
				if joined := strings.Join(args, " "); strings.Contains(joined, "hooks remove-all") && !strings.HasSuffix(joined, " --check") {
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

// GAP-0185: an agent must never be left with a DefenseClaw hook
// registration that names a removed hook binary while the deployment's policy
// is in force (the agent runs a missing command as a non-blocking hook error
// and the tool call runs). Uninstall removes every per-user and machine-policy
// registration while the hook binary and the runtime descriptor are still in
// place, so a hook started from a registration up to that point either gets
// the gateway's decision or fails closed (descriptor present, gateway
// stopping). Only then are the binaries removed.
func TestUninstallRemovesRegistrationsWhileTheHookBinaryExists(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			hook := h.env.P(filepath.Join(h.env.Layout.BinDir, binHook))
			descriptor := h.env.P(h.env.Layout.DescriptorPath)
			if !exists(hook) || !exists(descriptor) {
				t.Fatalf("install left no hook binary (%v) or descriptor (%v)", exists(hook), exists(descriptor))
			}
			var problems []string
			check := func(step string) {
				if !exists(hook) {
					problems = append(problems, step+": the hook binary was already removed")
				}
				if !exists(descriptor) {
					problems = append(problems, step+": the runtime descriptor was already removed")
				}
			}
			removeAll, policyRemoved := false, false
			h.env.Runner = observingRunner{Runner: h.runner, observe: func(name string, args []string) {
				if joined := strings.Join(args, " "); strings.Contains(joined, "hooks remove-all") && !strings.HasSuffix(joined, " --check") {
					removeAll = true
					check("per-user remove-all")
				}
			}}
			h.env.MachinePolicy = observingPolicy{MachinePolicyManager: h.env.MachinePolicy, observe: func() {
				policyRemoved = true
				check("machine policy removal")
			}}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if !removeAll || !policyRemoved {
				t.Fatalf("uninstall skipped a registration removal: per-user=%v machine-policy=%v", removeAll, policyRemoved)
			}
			if len(problems) > 0 {
				t.Fatalf("registrations outlived the hook binary they name:\n%s", strings.Join(problems, "\n"))
			}
			if goos == "darwin" && exists(hook) {
				t.Fatal("the macOS uninstall kept the hook binary")
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

// removeAllRunner answers `enterprise hooks remove-all` with answer, and
// its --check preflight with check (nil: every row resolves).
type removeAllRunner struct {
	Runner
	answer func(args string) (CommandResult, error)
	check  func() (CommandResult, error)
}

func (r removeAllRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if joined := strings.Join(args, " "); strings.HasPrefix(joined, "enterprise hooks remove-all ") {
		if !strings.HasSuffix(joined, " --check") {
			return r.answer(joined)
		}
		if r.check == nil {
			return CommandResult{Stdout: []byte(`{"ok":true}`)}, nil
		}
		return r.check()
	}
	return r.Runner.Run(ctx, name, args...)
}

// GAP-1101: a manifest row remove-all cannot resolve (no such account, a
// home-only row whose owner is unknown) failed the uninstall only after the
// services were unloaded and part of the machine policy was removed. The
// preflight names the row and refuses before anything changes.
func TestUninstallRefusesUnresolvedRowsBeforeStoppingAnything(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				t.Fatal("remove-all ran after its preflight refused")
				return CommandResult{}, nil
			}, check: func() (CommandResult, error) {
				return CommandResult{ExitCode: 1, Stdout: []byte(`{"ok":false,"failed":["/Users/gone/claudecode: user home /Users/gone: no such file or directory"]}`)}, errors.New("exit 1")
			}}
			h.env.MachinePolicy = observingPolicy{MachinePolicyManager: h.env.MachinePolicy, observe: func() {
				t.Fatal("the machine policy was removed after the preflight refused")
			}}
			before := len(h.services.calls)
			refused := h.run(Options{Action: ActionUninstall, Purge: true})
			requireError(t, refused, codePerUserHooks)
			requireError(t, refused, codeUninstallPrecheck)
			if got := messagesOf(refused.Errors, codePerUserHooks); !strings.Contains(got, "claudecode manifest row of user /Users/gone cannot be removed") {
				t.Fatalf("the refusal does not name the row: %s", got)
			}
			for _, call := range h.services.calls[before:] {
				if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "disable ") {
					t.Fatalf("the refused uninstall ran %q", call)
				}
			}
			if !exists(h.env.deploymentPath()) {
				t.Fatal("the refused uninstall removed the deployment record")
			}
		})
	}
}

// A precheck command can fail before it identifies any manifest rows (for
// example while parsing an untrusted manifest). The deployment stays intact.
func TestUninstallRefusesFailedHookPrecheckBeforeStoppingAnything(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		t.Fatal("remove-all ran after its precheck failed")
		return CommandResult{}, nil
	}, check: func() (CommandResult, error) {
		return CommandResult{ExitCode: 1, Stdout: []byte(`{"ok":false}`)}, errors.New("invalid manifest")
	}}
	h.env.MachinePolicy = observingPolicy{MachinePolicyManager: h.env.MachinePolicy, observe: func() {
		t.Fatal("machine policy was removed after the precheck failed")
	}}
	before := len(h.services.calls)
	refused := h.run(Options{Action: ActionUninstall, Purge: true})
	requireError(t, refused, codeUninstallPrecheck)
	for _, call := range h.services.calls[before:] {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "disable ") {
			t.Fatalf("the refused uninstall ran %q", call)
		}
	}
	if !exists(h.env.deploymentPath()) {
		t.Fatal("the refused uninstall removed the deployment record")
	}
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
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":1,"purged":["alice"],"purged_detail":{"alice":{"data":true,"binaries":true,"gateway":true}}}`)}, nil
			}}
			failed := h.run(Options{Action: ActionUninstall, Purge: true})
			requireError(t, failed, codePerUserHooks)
			requireError(t, failed, codeUninstallIncomplete)
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

// failingRemovePolicy cannot withdraw DefenseClaw's machine policy entries
// while fail is set (an immutable Claude Code managed-settings file).
type failingRemovePolicy struct {
	MachinePolicyManager
	fail *bool
}

func (p failingRemovePolicy) RemoveAll() (enterprisepolicy.Result, error) {
	if *p.fail {
		return enterprisepolicy.Result{}, errors.New("claudecode: remove managed-settings.json: operation not permitted")
	}
	return p.MachinePolicyManager.RemoveAll()
}

// GAP-1321: a failed machine policy removal left the vendor policy calling a
// hook binary the uninstall then deleted, so the agent ran unguarded. The
// binaries, record and state stay until a rerun can withdraw the policy.
// GAP-1500: the gateway and its sockets stayed stopped and disabled, so the
// retained hooks got no decisions; the services are put back as they were.
func TestUninstallKeepsTheBinariesWhileMachinePolicyRemains(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	ctx := context.Background()
	running, enabled := map[string]bool{}, map[string]bool{}
	for _, unit := range h.services.Units() {
		running[unit.Name] = h.services.Active(ctx, unit)
		enabled[unit.Name] = h.services.Enabled(ctx, unit)
	}
	fail := true
	h.env.MachinePolicy = failingRemovePolicy{MachinePolicyManager: h.env.MachinePolicy, fail: &fail}
	removedUsers := 0
	h.env.Runner = observingRunner{Runner: h.runner, observe: func(_ string, args []string) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "hooks remove-all") && !strings.HasSuffix(joined, " --check") {
			removedUsers++
		}
	}}
	failed := h.run(Options{Action: ActionUninstall, Purge: true})
	if removedUsers != 0 {
		t.Fatalf("machine policy removal failed after %d per-user hook removals", removedUsers)
	}
	requireError(t, failed, codeUninstall)
	// GAP-1519: the stop has its own code, which the package removal keeps
	// the package files on.
	requireError(t, failed, codeUninstallIncomplete)
	if got := messagesOf(failed.Errors, codeUninstall); !strings.Contains(got, "operation not permitted") {
		t.Fatalf("the uninstall does not name the policy failure: %s", got)
	}
	if got := messagesOf(failed.Errors, codeUninstallIncomplete); !strings.Contains(got, h.env.lifecycleCommand(ActionUninstall)+" --purge`") {
		t.Fatalf("the uninstall does not name the rerun: %s", got)
	}
	hook := h.env.P(filepath.Join(h.env.Layout.BinDir, binHook))
	if !exists(hook) || !exists(h.env.deploymentPath()) {
		t.Fatal("the uninstall removed the hook binary the machine policy still names")
	}
	for _, unit := range h.services.Units() {
		if h.services.Active(ctx, unit) != running[unit.Name] || h.services.Enabled(ctx, unit) != enabled[unit.Name] {
			t.Errorf("%s: active %v enabled %v after the refused uninstall, was %v %v", unit.Name,
				h.services.Active(ctx, unit), h.services.Enabled(ctx, unit), running[unit.Name], enabled[unit.Name])
		}
	}
	if code, _, err := h.env.HealthGet(ctx); err != nil || code != 200 {
		t.Fatalf("the gateway the retained hooks call is not ready: %d %v", code, err)
	}
	fail = false
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if exists(hook) || exists(h.env.deploymentPath()) {
		t.Fatal("the rerun did not finish the removal")
	}
}

// r102 GAP-0473: an uninstall that could not remove the Claude Code drop-in
// (a read-only folder here, an immutable file on a host) had already
// removed the Codex requirements. The deployment stays, so the Codex entries
// go back before its services start again.
func TestUninstallStoppedByMachinePolicyRestoresTheRemovedPolicy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only folder")
	}
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex", "claudecode")}))
	hook := enterprisepolicy.HookBinaryPath(h.env.Layout)
	dropIns := h.env.P(filepath.Dir(claudeDropIn))
	if err := os.Chmod(dropIns, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dropIns, 0o755) })
	failed := h.run(Options{Action: ActionUninstall})
	requireError(t, failed, codeUninstallIncomplete)
	if !strings.Contains(h.read(claudeDropIn), hook) {
		t.Fatal("test setup: the Claude Code drop-in was removed")
	}
	if !exists(h.env.P(codexRequirements)) || !strings.Contains(h.read(codexRequirements), hook) {
		t.Fatal("the stopped uninstall left the Codex machine policy removed")
	}
	if _, ok := failed.MachinePolicy["codex"]; ok {
		t.Fatalf("the result reports the restored Codex policy as removed: %+v", failed.MachinePolicy)
	}
	if err := os.Chmod(dropIns, 0o755); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if exists(h.env.P(codexRequirements)) && strings.Contains(h.read(codexRequirements), hook) {
		t.Fatal("the rerun did not remove the Codex machine policy")
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
	if got := purgedUserChange("carol", purgedUserDetail{}); got != "found no DefenseClaw per-user data or binaries of user carol to remove" {
		t.Fatalf("an account with nothing to remove: %q", got)
	}
	// GAP-1947: the uv cache entries the purge removed are named too.
	if got := purgedUserChange("dave", purgedUserDetail{Data: true, UVCache: true}); !strings.Contains(got, "~/.defenseclaw") ||
		!strings.HasSuffix(got, "and DefenseClaw's entries in its uv cache (~/.cache/uv)") {
		t.Fatalf("an account with uv cache entries: %q", got)
	}
	if got := purgedUserChange("erin", purgedUserDetail{UVCache: true}); got != "removed DefenseClaw's entries in the uv cache (~/.cache/uv) of user erin" {
		t.Fatalf("an account with only uv cache entries: %q", got)
	}
}

// GAP-1186: an account enrolled only for machine-policy connectors (Claude
// Code) has no manifest row, so the per-user purge left the session cache
// the managed hook wrote in its home. The purge removes the cache and the
// ~/.defenseclaw it leaves empty, keeps a folder with other files in it,
// and does not follow a cache that is a symlink.
func TestUninstallPurgeRemovesTheSessionFactsCache(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	uid := os.Getuid()
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), fmt.Sprintf(
		`{"accounts":[{"user":"alice","uid":%d,"home":"/home/alice"},{"user":"bob","uid":%d,"home":"/home/bob"},{"user":"carol","uid":%d,"home":"/home/carol"}]}`,
		uid, uid, uid))
	writeHostFile(t, h, "/home/alice/.defenseclaw/session-facts.json", "{}")
	writeHostFile(t, h, "/home/bob/.defenseclaw/session-facts.json", "{}")
	writeHostFile(t, h, "/home/bob/.defenseclaw/notes.txt", "kept")
	writeHostFile(t, h, "/home/carol/.defenseclaw/notes.txt", "kept")
	writeHostFile(t, h, "/srv/elsewhere.json", "{}")
	if err := os.Symlink(h.env.P("/srv/elsewhere.json"), h.env.P("/home/carol/.defenseclaw/session-facts.json")); err != nil {
		t.Fatal(err)
	}
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true}`)}, nil
	}}
	done := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, done)
	if exists(h.env.P("/home/alice/.defenseclaw")) || exists(h.env.P("/home/bob/.defenseclaw/session-facts.json")) ||
		!exists(h.env.P("/home/bob/.defenseclaw/notes.txt")) || !exists(h.env.P("/srv/elsewhere.json")) {
		t.Fatalf("purge left the cache, removed other files or followed a symlink; changes %v", done.Changes)
	}
	if got := messagesOf(done.Warnings, codePerUserState); !strings.Contains(got, "user carol") {
		t.Fatalf("the symlinked cache of carol is not reported: %q", got)
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

// GAP-0960: the plain uninstall of a package host keeps the administrator
// policies (a custom rule pack), so the documented re-enable, `ensure
// --from-package --config` with the same config, works. The vendor policies
// go, empty folders included (GAP-1582). A purge removes everything.
func TestUninstallKeepsTheAdministratorPoliciesForTheReenable(t *testing.T) {
	h := packageHost(t, "1.0.0")
	l := h.env.Layout
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	vendor, custom := filepath.Join(l.VendorPolicyDir, "guardrail", "default"), filepath.Join(l.PolicyDir, "guardrail", "custom")
	if err := filepath.WalkDir(h.env.P(vendor), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(h.env.P(vendor), path)
		data, err := os.ReadFile(path)
		if err == nil {
			writeHostFile(t, h, filepath.Join(custom, rel), string(data))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(l.PolicyDir), 0o755); err != nil { // the service account reaches the pack
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	raw := strings.Replace(v8AdminConfig(l), "rule_pack_dir: "+vendor, "rule_pack_dir: "+custom, 1)
	if err := os.WriteFile(cfg, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	reenable := Options{Action: ActionEnsure, FromPackage: true, ConfigFile: cfg}
	requireOK(t, h.run(reenable))

	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	if exists(h.env.P(l.ConfigPath)) || !exists(h.env.P(filepath.Join(custom, "rules"))) || exists(h.env.P(l.VendorPolicyDir)) {
		t.Fatalf("plain uninstall: config kept=%v, custom pack kept=%v, vendor policies kept=%v",
			exists(h.env.P(l.ConfigPath)), exists(h.env.P(custom)), exists(h.env.P(vendor)))
	}
	if summary := strings.Join(r.Changes, "\n"); !strings.Contains(summary, "kept the administrator policies in "+l.PolicyDir) ||
		!strings.Contains(summary, "--from-package --config <file>") {
		t.Fatalf("uninstall summary does not name the kept policies and the package re-enable:\n%s", summary)
	}
	requireOK(t, h.run(reenable))

	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if exists(h.env.P(l.ConfigDir)) || exists(h.env.P(l.VendorPolicyDir)) {
		t.Fatal("purge kept the administrator or vendor policies")
	}
}

// A payload uninstall removes the binaries, so the kept policies come with a
// payload reinstall step rather than ensure --from-package. A policies folder
// with a file in an administrator pack stays; folders staged for a pack
// that never got a file go with the config, like the empty folder the
// install created (GAP-1582).
func TestPayloadUninstallKeepsPolicyFoldersWithFilesAndNamesThePayloadReinstall(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stage, file bool
	}{{"none", false, false}, {"empty staged folder", true, false}, {"pack file", true, true}} {
		h := newTestHost(t, "linux")
		l := h.env.Layout
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		pack := filepath.Join(l.PolicyDir, "guardrail", "custom")
		if tc.stage {
			if err := os.MkdirAll(h.env.P(filepath.Join(pack, "judge")), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if tc.file {
			writeHostFile(t, h, filepath.Join(pack, "rules", "admin.yaml"), "# admin rule\n")
		}
		r := h.run(Options{Action: ActionUninstall})
		requireOK(t, r)
		summary := strings.Join(r.Changes, "\n")
		if exists(h.env.P(filepath.Join(pack, "rules", "admin.yaml"))) != tc.file || exists(h.env.P(l.PolicyDir)) != tc.file ||
			exists(h.env.P(filepath.Join(pack, "judge"))) || strings.Contains(summary, "kept the administrator policies") != tc.file {
			t.Fatalf("%s: pack file kept=%v, policies kept=%v, empty judge kept=%v, summary:\n%s", tc.name,
				exists(h.env.P(filepath.Join(pack, "rules", "admin.yaml"))), exists(h.env.P(l.PolicyDir)), exists(h.env.P(filepath.Join(pack, "judge"))), summary)
		}
		if tc.file && (!strings.Contains(summary, "ensure --payload <payload> --config <file>") || strings.Contains(summary, "--from-package")) {
			t.Fatalf("payload uninstall summary does not give the payload reinstall step:\n%s", summary)
		}
	}
}

// emptyDirsUnder lists the directories under root (root included) that hold
// no file anywhere below them.
func emptyDirsUnder(t *testing.T, root string) []string {
	t.Helper()
	var empty []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && !holdsState(path) {
			empty = append(empty, path)
		}
		return nil
	})
	return empty
}

// GAP-1582: on a package host the plain uninstall removed the vendor policy
// files but kept their folders, so the re-enable with a default-pack config,
// `ensure --from-package --config`, found guardrail/default empty and the
// gateway pack check refused it (inventory_empty); 1.0.0 removed the
// folder. Every folder left without a file goes now, vendor or
// administrator; a folder with an administrator file stays.
func TestPackageUninstallLeavesNoEmptyPolicyFoldersSoTheReenableWorks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		customFile bool // an administrator rule pack file in PolicyDir
		emptyOnly  bool // empty folders staged in both policy dirs
	}{{"vendor files only", false, false}, {"vendor files and a custom pack file", true, false}, {"empty folders left behind", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := packageHost(t, "1.0.0")
			l := h.env.Layout
			vendor := filepath.Join(l.VendorPolicyDir, "guardrail", "default")
			// The gateway check, as far as this needs it: a pack folder
			// with no rule-pack file is refused.
			config.RegisterCandidateAssetCheck(func(*config.Config) error {
				if dir := h.env.P(vendor); exists(dir) && !holdsState(dir) {
					return errors.New("config rule pack \"" + vendor + "\": rule pack inventory_empty at .: directory contains no recognized rule-pack component")
				}
				return nil
			})
			t.Cleanup(func() { config.RegisterCandidateAssetCheck(nil) })
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(cfg, []byte(v8AdminConfig(l)), 0o600); err != nil {
				t.Fatal(err)
			}
			reenable := Options{Action: ActionEnsure, FromPackage: true, ConfigFile: cfg}
			requireOK(t, h.run(reenable))
			customFile := filepath.Join(l.PolicyDir, "guardrail", "custom", "rules", "admin.yaml")
			if tc.customFile {
				writeHostFile(t, h, customFile, "# admin rule\n")
			}
			if tc.emptyOnly {
				for _, dir := range []string{filepath.Join(l.PolicyDir, "guardrail", "custom", "judge"), filepath.Join(l.VendorPolicyDir, "guardrail", "extra")} {
					if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}

			r := h.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			if empty := append(emptyDirsUnder(t, h.env.P(l.VendorPolicyDir)), emptyDirsUnder(t, h.env.P(l.PolicyDir))...); len(empty) > 0 {
				t.Fatalf("plain uninstall left folders without a file: %v", empty)
			}
			if exists(h.env.P(vendor)) {
				t.Fatal("plain uninstall kept the vendor pack")
			}
			if exists(h.env.P(customFile)) != tc.customFile || exists(h.env.P(l.PolicyDir)) != tc.customFile {
				t.Fatalf("custom pack file kept=%v, policies kept=%v, want %v", exists(h.env.P(customFile)), exists(h.env.P(l.PolicyDir)), tc.customFile)
			}

			requireOK(t, h.run(reenable))
			if !holdsState(h.env.P(vendor)) {
				t.Fatal("the re-enable did not write the vendor pack again")
			}
			if tc.customFile && h.read(customFile) != "# admin rule\n" {
				t.Fatal("the re-enable changed the custom pack file")
			}
		})
	}
}

// spawnScheduledServices reports label loaded but not running, as launchd
// reports a KeepAlive job between two runs ("spawn scheduled").
type spawnScheduledServices struct {
	*fakeServices
	label string
}

func (s spawnScheduledServices) Active(ctx context.Context, unit Unit) bool {
	if unit.Name == s.label {
		return false
	}
	return s.fakeServices.Active(ctx, unit)
}

func (s spawnScheduledServices) Loaded(_ context.Context, unit Unit) bool {
	return s.isActive(unit.Name)
}

// GAP-1520: an uninstall that stops short of removing the deployment puts
// back the services it stopped (GAP-1500), but on macOS it put back only the
// jobs that were "running" when it looked: a KeepAlive gateway launchd was
// about to respawn stayed unloaded. A loaded job is loaded again.
func TestRefusedUninstallLoadsASpawnScheduledJobAgain(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if !h.services.isActive(labelGateway) {
		t.Fatal("the gateway job is not loaded after install")
	}
	h.env.Services = spawnScheduledServices{fakeServices: h.services, label: labelGateway}
	fail := true
	h.env.MachinePolicy = failingRemovePolicy{MachinePolicyManager: h.env.MachinePolicy, fail: &fail}
	refused := h.run(Options{Action: ActionUninstall})
	requireError(t, refused, codeUninstallIncomplete)
	if !h.services.isActive(labelGateway) {
		t.Fatalf("the refused uninstall left the spawn-scheduled gateway job unloaded; calls: %v", h.services.calls)
	}
}

func TestRefusedMacUninstallChecksRestoredGatewayAsServiceAccount(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	record, err := h.env.loadDeployment()
	if err != nil || record.ServiceUID <= 0 {
		t.Fatalf("service uid: %+v %v", record, err)
	}
	fail := true
	h.env.MachinePolicy = failingRemovePolicy{MachinePolicyManager: h.env.MachinePolicy, fail: &fail}
	refused := h.run(Options{Action: ActionUninstall})
	requireError(t, refused, codeUninstallIncomplete)
	if got := messagesOf(refused.Errors, codeUninstall); strings.Contains(got, "served by uid") ||
		strings.Contains(got, "did not become ready") {
		t.Fatalf("restored gateway was checked against the wrong service uid: %s", got)
	}
}

// GAP-1140: a remove-all failure that names no registration (an unreadable
// eligible-accounts file) was only a warning, so the uninstall removed the
// binaries the registrations it could not check may still call. It keeps
// them, as for a named registration, and the rerun finishes.
func TestUninstallKeepsTheBinariesWhenRegistrationsWereNotChecked(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{ExitCode: 1, Stdout: []byte(`{"ok":false,"failed":["eligible accounts: open unix_eligible_accounts.json: permission denied"]}`)}, errors.New("exit 1")
	}}
	failed := h.run(Options{Action: ActionUninstall})
	requireError(t, failed, codePerUserHooks)
	requireError(t, failed, codeUninstallIncomplete)
	if got := messagesOf(failed.Errors, codePerUserHooks); !strings.Contains(got, "were not checked: eligible accounts") {
		t.Fatalf("the uninstall does not name the unchecked registrations: %s", got)
	}
	gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	if !exists(gateway) || !exists(h.env.deploymentPath()) {
		t.Fatal("the uninstall removed the binaries while registrations were not checked")
	}
	for _, report := range []string{"invalid report", `{}`, `{"ok":false}`} {
		h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
			return CommandResult{Stdout: []byte(report)}, nil
		}}
		refused := h.run(Options{Action: ActionUninstall})
		requireError(t, refused, codeUninstallIncomplete)
		if !exists(gateway) || !exists(h.env.deploymentPath()) ||
			!strings.Contains(messagesOf(refused.Errors, codePerUserHooks), h.env.lifecycleCommand(ActionUninstall)) {
			t.Fatalf("unconfirmed hook removal did not retain the deployment and name its retry: %+v", refused)
		}
	}
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true}`)}, nil
	}}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if exists(gateway) || exists(h.env.deploymentPath()) {
		t.Fatal("the rerun did not finish the removal")
	}
}

// GAP-1440: the uninstall removed the lifecycle state, the deployment record
// with it, before it knew every state folder was gone; when one could not be
// removed, the rerun found no record and was a not_installed no-op. The
// record stays until the removal is complete.
func TestUninstallKeepsTheRecordWhenAStateFolderStays(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	parent := filepath.Dir(h.env.P(h.env.Layout.LogDir))
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	requireError(t, h.run(Options{Action: ActionUninstall}), codeUninstall)
	if !exists(h.env.deploymentPath()) {
		t.Fatal("the failed uninstall removed the deployment record")
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	retry := h.run(Options{Action: ActionUninstall})
	requireOK(t, retry)
	if retry.Noop || exists(h.env.deploymentPath()) || exists(h.env.P(h.env.Layout.LogDir)) {
		t.Fatalf("the rerun did not finish the removal (noop %v)", retry.Noop)
	}
}
