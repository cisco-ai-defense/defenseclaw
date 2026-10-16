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

// GAP-0553: when remove-all reports a user's registrations as pending (the
// user's home is not available, or is gone with a removed AD mobile
// account), a managed uninstall without --purge warns per_user_hooks_remaining
// for that user and agent and goes on: the binaries and the deployment go.
func TestUninstallWarnsAndGoesOnForAPerUserHomeThatIsNotAvailable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["sample-user/hermes"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			requireOK(t, done)
			got := messagesOf(done.Warnings, codePerUserHooks)
			if !strings.Contains(got, "hermes hooks for user sample-user were not removed because that account's home is not available") {
				t.Fatalf("the uninstall does not warn for the user whose home is not available: %q", got)
			}
			if messagesOf(done.Errors, codePerUserHooks) != "" || messagesOf(done.Errors, codeUninstallIncomplete) != "" {
				t.Fatalf("a home that is not available must not stop the uninstall: %+v", done.Errors)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall did not remove the binaries and the deployment record")
			}
		})
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
