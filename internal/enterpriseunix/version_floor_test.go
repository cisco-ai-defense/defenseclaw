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
	"os"
	"path"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

const wantClaudeVersionFloor = "{\n  \"requiredMinimumVersion\": \"2.1.154\"\n}\n"

var claudeVersionFloorDropIn = "/etc/claude-code/managed-settings.d/" + enterprisepolicy.ClaudeVersionFloorDropInName

// Install writes the Claude Code version floor next to the hook drop-in,
// ensure keeps it, and uninstall removes it.
func TestInstallWritesAndUninstallRemovesTheClaudeVersionFloor(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			floor := claudeVersionFloorDropIn
			if goos == "darwin" {
				floor = path.Join("/Library/Application Support/ClaudeCode/managed-settings.d", enterprisepolicy.ClaudeVersionFloorDropInName)
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			if got := h.read(floor); got != wantClaudeVersionFloor {
				t.Fatalf("floor drop-in = %q", got)
			}
			if noop := h.run(Options{Action: ActionEnsure}); !noop.Noop {
				t.Fatalf("ensure after install must be a no-op: %+v", noop.Warnings)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if exists(h.env.P(floor)) {
				t.Fatal("uninstall kept DefenseClaw's Claude Code version floor")
			}
		})
	}
}

// An administrator's floor is theirs: a file at DefenseClaw's own drop-in
// name (the version-floor export), or a requiredMinimumVersion in the base
// managed settings. Install, ensure and uninstall leave it byte for byte,
// DefenseClaw writes no floor of its own over it, and it is not incomplete
// machine policy.
func TestInstallKeepsAnAdministratorClaudeVersionFloor(t *testing.T) {
	for _, tc := range []struct{ name, file, content string }{
		{"file at the floor name", claudeVersionFloorDropIn, wantClaudeVersionFloor},
		{"value in the base settings", "/etc/claude-code/managed-settings.json", "{\"requiredMinimumVersion\": \"2.1.300\"}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			if err := os.MkdirAll(h.env.P(path.Dir(tc.file)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(tc.file), []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")})
			requireOK(t, r)
			if hasWarning(r, codeMachinePolicyIncomplete) {
				t.Fatalf("an administrator floor is not incomplete machine policy: %+v", r.Warnings)
			}
			if tc.file != claudeVersionFloorDropIn && exists(h.env.P(claudeVersionFloorDropIn)) {
				t.Fatal("DefenseClaw wrote a floor over an administrator requiredMinimumVersion")
			}
			if noop := h.run(Options{Action: ActionEnsure}); !noop.Noop {
				t.Fatalf("ensure after install must be a no-op: %+v", noop.Warnings)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if got := h.read(tc.file); got != tc.content {
				t.Fatalf("install or uninstall changed the administrator's file: %q", got)
			}
		})
	}
}
