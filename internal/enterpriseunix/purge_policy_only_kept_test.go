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
// "enrolled user" with an account-owned folder. An account with its own
// install keeps that warning (GAP-0727), and nothing is deleted.
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
				`{"accounts":[{"user":"std1","uid":%d,"home":"%sstd1"},{"user":"eng1","uid":%d,"home":"%seng1"},{"user":"own1","uid":%d,"home":"%sown1"}]}`,
				uid, homes, uid, homes, uid, homes))
			writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: std1\n    connector: kiro\n")
			hook := homes + "eng1/.defenseclaw/hooks/copilot-hook.sh"
			writeHostFile(t, h, hook, "#!/bin/sh\n")
			writeHostFile(t, h, homes+"eng1/.defenseclaw/connector_backups/copilot.json", "{}")
			writeHostFile(t, h, homes+"own1/.defenseclaw/config.yaml", "guardrail: {}\n")
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
				strings.Contains(got, "data (~/.defenseclaw) of eng1, own1") || strings.Contains(got, "of std1, ") {
				t.Fatalf("the purge does not name eng1 alone on the machine-policy kept: line: %q", got)
			}
			if !strings.Contains(got, "for enrolled user own1") || !strings.Contains(got, "for enrolled user std1") {
				t.Fatalf("the purge no longer names the accounts whose folder stays as enrolled user data: %q", got)
			}
			if h.read(hook) != "#!/bin/sh\n" || h.read(homes+"own1/.defenseclaw/config.yaml") != "guardrail: {}\n" {
				t.Fatal("the purge report changed an account's files")
			}
		})
	}
}
