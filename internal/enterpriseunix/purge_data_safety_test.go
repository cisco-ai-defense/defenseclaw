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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0727: the purge names the account whose own per-user install from
// before the managed deployment it kept as it is; nothing was moved.
func TestUninstallPurgeNamesTheKeptPerUserInstall(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"purged":["alice","bob"],` +
					`"purged_detail":{"alice":{"kept":true},"bob":{"data":true}}}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			var alice, bob string
			for _, change := range done.Changes {
				switch {
				case strings.Contains(change, "of user alice "):
					alice = change
				case strings.Contains(change, "of user bob "):
					bob = change
				}
			}
			if !strings.HasPrefix(alice, "kept the DefenseClaw per-user data of user alice (~/.defenseclaw) as it is") ||
				strings.Contains(alice, "backup") || strings.Contains(alice, "moved to") {
				t.Fatalf("the purge does not name alice's kept install: %q", alice)
			}
			if !strings.HasPrefix(bob, "removed ") {
				t.Fatalf("bob's managed-only data was not removed: %q", bob)
			}
		})
	}
}

// GAP-0727: a machine-policy-only enrollment can leave a pre-existing OSS
// installation untouched. The result must name the retained account data;
// lifecycle reporting never deletes or moves the account's files.
func TestUnixPurgeReportsAnEnrolledOSSInstallItLeavesBehind(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			home := "/home/alice"
			if goos == "darwin" {
				home = "/Users/alice"
			}
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), fmt.Sprintf(
				`{"accounts":[{"user":"alice","uid":%d,"home":"%s"}]}`, os.Getuid(), home))
			record := h.env.P(enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath))
			config := filepath.Join(home, ".defenseclaw", "config.yaml")
			writeHostFile(t, h, config, "guardrail: {}\n")
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				// The real remove-all worker removes this record before lifecycle
				// reports what survived. Its pre-removal snapshot must suffice.
				if err := os.Remove(record); err != nil {
					t.Fatal(err)
				}
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			if _, err := os.Lstat(record); !os.IsNotExist(err) {
				t.Fatalf("worker did not remove enrollment record: %v", err)
			}
			if got := h.read(config); got != "guardrail: {}\n" {
				t.Fatalf("purge changed the account's OSS data: %q", got)
			}
			if got := messagesOf(done.Warnings, codePerUserState); !strings.Contains(got, "alice") ||
				!strings.Contains(got, "~/.defenseclaw") || !strings.Contains(got, "kept") {
				t.Fatalf("purge omitted retained OSS data from its result: %q", got)
			}
		})
	}
}

// GAP-0582: a purge that keeps an account's per-user state (its pending
// cleanup still needs it) also keeps that account's session-facts cache;
// the other accounts' caches go.
func TestUninstallPurgeKeepsTheSessionCacheOfAnAccountWhoseStateStays(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	uid := os.Getuid()
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), fmt.Sprintf(
		`{"accounts":[{"user":"alice","uid":%d,"home":"/home/alice"},{"user":"kept","uid":%d,"home":"/home/kept"}]}`, uid, uid))
	writeHostFile(t, h, "/home/alice/.defenseclaw/session-facts.json", "{}")
	writeHostFile(t, h, "/home/kept/.defenseclaw/session-facts.json", "{}")
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"state_failed":["kept: its recorded home may still hold a hook registration; the state stays while cleanup is unresolved"]}`)}, nil
	}}
	done := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, done)
	if exists(h.env.P("/home/alice/.defenseclaw/session-facts.json")) {
		t.Fatalf("the purge left alice's session cache; changes %v", done.Changes)
	}
	if !exists(h.env.P("/home/kept/.defenseclaw/session-facts.json")) {
		t.Fatalf("the purge removed the session cache of an account whose state stays; changes %v", done.Changes)
	}
	if got := messagesOf(done.Warnings, codePerUserState); !strings.Contains(got, "user kept were not removed") {
		t.Fatalf("the kept state is not named: %q", got)
	}
}

// #1287: an enrolled account whose home folder is gone (a macOS mobile
// account's home moved away, say) does not stop a purge: remove-all
// reports it already clean, the uninstall warns with that reason and
// removes the deployment.
func TestUninstallPurgeGoesOnForAnAccountWhoseHomeIsGone(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			reason := "its home /Users/ctr1 no longer exists, so no DefenseClaw hook registration is left there; if that home is restored, remove DefenseClaw's entries from the codex config in it"
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"pending":["ctr1/codex: ` + reason + `"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			if got := messagesOf(done.Warnings, codePerUserHooks); !strings.Contains(got, "codex hooks for user ctr1 were not removed: "+reason) {
				t.Fatalf("the uninstall does not warn with the gone home: %q", got)
			}
			if messagesOf(done.Errors, codePerUserHooks) != "" || messagesOf(done.Errors, codeUninstallIncomplete) != "" {
				t.Fatalf("a gone home must not stop the purge: %+v", done.Errors)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || exists(h.env.deploymentPath()) {
				t.Fatal("the purge did not remove the binaries and the deployment record")
			}
		})
	}
}
