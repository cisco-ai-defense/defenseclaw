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
			requireOK(t, h.run(Options{Action: ActionUninstall}))
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
			// MAC-U2-13: and says the disabled hook stubs stay.
			if !strings.Contains(strings.Join(done.Changes, "\n"), "except ~/.defenseclaw/hooks") {
				t.Fatalf("the purge report does not say the hook stubs stay: %v", done.Changes)
			}
		})
	}
}
