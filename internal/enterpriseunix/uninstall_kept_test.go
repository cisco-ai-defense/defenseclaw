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

func TestUninstallPurgeKeptOwnInstallWarnings(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
	uid := os.Getuid()
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), fmt.Sprintf(
		`{"accounts":[{"user":"restored","uid":%d,"home":"/Users/restored"},{"user":"policy","uid":%d,"home":"/Users/policy"}]}`,
		uid, uid))
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: policy\n    connector: kiro\n")
	writeHostFile(t, h, "/Users/restored/.defenseclaw/config.yaml", "guardrail: {}\n")
	writeHostFile(t, h, "/Users/policy/.defenseclaw/hooks/kiro-hook.sh", "#!/bin/sh\n")
	writeHostFile(t, h, "/Users/unnamed/.defenseclaw/config.yaml", "guardrail: {}\n")
	writeHostFile(t, h, "/Users/one-liner/.defenseclaw/.venv/bin/defenseclaw", "#!/bin/sh\n")
	writeHostFile(t, h, "/Users/one-liner/.defenseclaw/installer/binaries.sha256", "sample\n")
	writeHostFile(t, h, "/Users/leftover/.defenseclaw/hooks/kiro-hook.sh", "#!/bin/sh\n")
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"own_install_restored":["restored"]}`)}, nil
	}}
	done := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, done)
	warnings := messagesOf(done.Warnings, codePerUserState)
	changes := strings.Join(done.Changes, "\n")
	if !strings.Contains(changes, "put back the own per-user DefenseClaw files of user restored") ||
		strings.Contains(warnings, "kept the own DefenseClaw install of user restored") {
		t.Fatalf("restored account report: changes=%q warnings=%q", changes, warnings)
	}
	for _, user := range []string{"unnamed", "one-liner"} {
		if !strings.Contains(warnings, "kept the own DefenseClaw install of user "+user+" after --purge: this deployment did not enroll this account") {
			t.Fatalf("unnamed account %s report: %q", user, warnings)
		}
	}
	if !strings.Contains(warnings, "for enrolled user policy") {
		t.Fatalf("account without its own install lost the enrolled-user warning: %q", warnings)
	}
	if !strings.Contains(warnings, "data (~/.defenseclaw) of leftover, accounts this deployment did not enroll") ||
		strings.Contains(warnings, "kept the own DefenseClaw install of user leftover") {
		t.Fatalf("account with only leftover hooks lost the generic warning: %q", warnings)
	}
	if h.read("/Users/restored/.defenseclaw/config.yaml") != "guardrail: {}\n" ||
		h.read("/Users/unnamed/.defenseclaw/config.yaml") != "guardrail: {}\n" ||
		h.read("/Users/one-liner/.defenseclaw/.venv/bin/defenseclaw") != "#!/bin/sh\n" {
		t.Fatal("reporting changed an account's files")
	}
}
