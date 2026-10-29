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
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0443 (was GAP-0553's warn-and-go-on rule): when remove-all reports a
// user's registrations as pending because that live account's home is not
// available, a managed uninstall without --purge stops before the binaries
// and the deployment go (uninstall_incomplete) and names the next step; a
// removed account's pending entry, which carries its reason, still warns
// and goes on (below).
func TestUninstallKeepsTheDeploymentForAPerUserHomeThatIsNotAvailable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["sample-user/hermes"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			// GAP-0443: the registrations in a home that is not available
			// (an unmounted volume) are kept as registrations: they would
			// call a deleted hook binary when the home returns. The
			// binaries and the deployment record stay so a rerun finishes.
			got := messagesOf(done.Errors, codePerUserHooks)
			if !strings.Contains(got, "hermes hooks for user sample-user were not removed because that account's home is not available, so a DefenseClaw registration may remain in it") ||
				!strings.Contains(got, "make that home available (mount its volume) and rerun") {
				t.Fatalf("the uninstall does not name the registration that may remain and the next step: %q", got)
			}
			// GAP-2134: an empty parent is also a deleted home of a
			// per-domain layout; recreating the folder is the step that
			// works. Removing the account does not: a targets.yaml row of
			// a removed account still stops the uninstall.
			if !strings.Contains(got, "if that home folder was deleted, recreate it as a folder the account owns and rerun") ||
				strings.Contains(got, "remove the account") {
				t.Fatalf("the uninstall offers a step that does not finish it, or not the one that does: %q", got)
			}
			if messagesOf(done.Errors, codeUninstallIncomplete) == "" {
				t.Fatalf("an uninstall that keeps the deployment must say it stopped: %+v", done.Errors)
			}
			if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || !exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall removed the binaries or the deployment record while a home was not available")
			}
			// Once the home is back, the rerun removes the rest.
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":1}`)}, nil
			}}
			rerun := h.run(Options{Action: ActionUninstall})
			requireOK(t, rerun)
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || exists(h.env.deploymentPath()) {
				t.Fatal("the rerun did not remove the binaries and the deployment record")
			}
		})
	}
}

// GAP-2358: the hook-removal precheck already names a live account whose
// home is not available. The uninstall refused only after remove-all had
// run, so the Claude Code blockers and hooks of every other user were gone
// and the services had stopped. It now refuses before anything changes; a
// pending entry with a reason (a home that is gone) does not refuse.
func TestUninstallRefusesBeforeAnyChangeForAPerUserHomeThatIsNotAvailable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			gone := "gone-user/codex: its home /home/gone-user no longer exists, so no DefenseClaw hook registration is left there; if that home is restored, remove DefenseClaw's entries from the codex config in it"
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				t.Fatal("remove-all ran (and removed the other users' hooks and blockers) after its precheck named a home that is not available")
				return CommandResult{}, nil
			}, check: func() (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["` + gone + `","sample-user/hermes"]}`)}, nil
			}}
			h.env.MachinePolicy = observingPolicy{MachinePolicyManager: h.env.MachinePolicy, observe: func() {
				t.Fatal("the machine policy was removed after the precheck named a home that is not available")
			}}
			before := len(h.services.calls)
			refused := h.run(Options{Action: ActionUninstall})
			requireError(t, refused, codeUninstallPrecheck)
			got := messagesOf(refused.Errors, codePerUserHooks)
			if !strings.Contains(got, "hermes hooks for user sample-user were not removed because that account's home is not available, so a DefenseClaw registration may remain in it") ||
				!strings.Contains(got, "make that home available (mount its volume) and rerun") {
				t.Fatalf("the refusal does not name the home that is not available and the next step: %q", got)
			}
			if strings.Contains(got, "gone-user") {
				t.Fatalf("a home that is gone must not refuse the uninstall: %q", got)
			}
			if len(refused.Changes) != 0 {
				t.Fatalf("the refused uninstall reports changes: %q", refused.Changes)
			}
			for _, call := range h.services.calls[before:] {
				if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "disable ") {
					t.Fatalf("the refused uninstall ran %q", call)
				}
			}
			if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || !exists(h.env.deploymentPath()) {
				t.Fatal("the refused uninstall removed the binaries or the deployment record")
			}
		})
	}
}

// A precheck whose only pending entry carries a reason (a home that is gone)
// does not refuse: the uninstall warns for it and completes (GAP-2358 keeps
// GAP-0553's rule).
func TestUninstallPrecheckDoesNotRefuseAHomeThatIsGone(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	gone := "gone-user/codex: its home /home/gone-user no longer exists, so no DefenseClaw hook registration is left there; if that home is restored, remove DefenseClaw's entries from the codex config in it"
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["` + gone + `"]}`)}, nil
	}, check: func() (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["` + gone + `"]}`)}, nil
	}}
	done := h.run(Options{Action: ActionUninstall})
	requireOK(t, done)
	if exists(h.env.deploymentPath()) {
		t.Fatal("the uninstall did not complete for a home that is gone")
	}
}

// GAP-0553: remove-all reports the pending cleanup of a removed account
// with a reason that names its recorded home and a remedy. The uninstall
// warns with that reason, not with "once it is available", and goes on.
func TestUninstallWarnsTheReasonOfARemovedAccountsPendingHooks(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			reason := "the directory gives the account no home (/var/empty), so it looks removed, but its recorded home /Users/dcad-kept is not gone and may still hold DefenseClaw's entries; remove them from the hermes config in /Users/dcad-kept, or delete that home if the account is gone"
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["dcad-kept/hermes: ` + reason + `"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			requireOK(t, done)
			got := messagesOf(done.Warnings, codePerUserHooks)
			if !strings.Contains(got, "DefenseClaw's hermes hooks for user dcad-kept were not removed: "+reason) || strings.Contains(got, "once it is") {
				t.Fatalf("the uninstall does not warn with the removed account's reason: %q", got)
			}
			if messagesOf(done.Errors, codePerUserHooks) != "" || messagesOf(done.Errors, codeUninstallIncomplete) != "" {
				t.Fatalf("a removed account's pending hooks must not stop the uninstall: %+v", done.Errors)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall did not remove the binaries and the deployment record")
			}
		})
	}
}
