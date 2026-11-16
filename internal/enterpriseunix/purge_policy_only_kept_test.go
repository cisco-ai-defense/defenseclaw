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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-2237: after a purge, an eligible account the enrollment manifest does
// not name (covered only by the machine policy) whose ~/.defenseclaw holds
// only the files DefenseClaw wrote is named on a kept: line, not as an
// "enrolled user" with an account-owned folder. An account the manifest
// does not name whose folder holds its own install, initialised or not, is
// named as a kept own install (GAP-0727, rel-1-0-6 GAP-0484); the named
// account keeps the enrolled-user warning, and nothing is deleted.
func TestUnixPurgeDoesNotCallMachinePolicyOnlyLeftoversEnrolledUserData(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			homes := "/home/"
			if goos == "darwin" {
				homes = "/Users/"
			}
			uid := os.Getuid()
			writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), fmt.Sprintf(
				`{"accounts":[{"user":"std1","uid":%d,"home":"%sstd1"},{"user":"eng1","uid":%d,"home":"%seng1"},{"user":"own1","uid":%d,"home":"%sown1"},{"user":"own2","uid":%d,"home":"%sown2"}]}`,
				uid, homes, uid, homes, uid, homes, uid, homes))
			writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: std1\n    connector: kiro\n")
			hook := homes + "eng1/.defenseclaw/hooks/copilot-hook.sh"
			writeHostFile(t, h, hook, "#!/bin/sh\n")
			writeHostFile(t, h, homes+"eng1/.defenseclaw/connector_backups/copilot.json", "{}")
			writeHostFile(t, h, homes+"own1/.defenseclaw/config.yaml", "guardrail: {}\n")
			// The one-liner install before `defenseclaw init`.
			writeHostFile(t, h, homes+"own2/.defenseclaw/.venv/bin/defenseclaw", "#!/bin/sh\n")
			writeHostFile(t, h, homes+"own2/.defenseclaw/installer/binaries.sha256", "sample\n")
			writeHostFile(t, h, homes+"std1/.defenseclaw/hooks/kiro-hook.sh", "#!/bin/sh\n")
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, done)
			got := messagesOf(done.Warnings, codePerUserState)
			if strings.Contains(got, "enrolled user eng1") {
				t.Fatalf("the purge calls the machine-policy-only leftovers of eng1 enrolled user data: %q", got)
			}
			if !strings.Contains(got, "kept: the DefenseClaw per-user data (~/.defenseclaw) of eng1, accounts the machine policy covered without a per-user enrollment") ||
				strings.Contains(got, "data (~/.defenseclaw) of eng1, own") || strings.Contains(got, "of std1, ") {
				t.Fatalf("the purge does not name eng1 alone on the machine-policy kept: line: %q", got)
			}
			if !strings.Contains(got, "for enrolled user std1") {
				t.Fatalf("the purge no longer names the enrolled account whose folder stays: %q", got)
			}
			for _, user := range []string{"own1", "own2"} {
				if !strings.Contains(got, "kept the own DefenseClaw install of user "+user+" (~/.defenseclaw and its binaries in ~/.local/bin) as it is after --purge: the enrollment did not name this account") ||
					strings.Contains(got, "for enrolled user "+user) {
					t.Fatalf("the purge does not name the own install of %s as kept: %q", user, got)
				}
			}
			if h.read(hook) != "#!/bin/sh\n" || h.read(homes+"own1/.defenseclaw/config.yaml") != "guardrail: {}\n" ||
				h.read(homes+"own2/.defenseclaw/.venv/bin/defenseclaw") != "#!/bin/sh\n" {
				t.Fatal("the purge report changed an account's files")
			}
		})
	}
}
