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
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestEnsureWithCodexDisabledTearsDownAndStatusSaysSo is rel-1-0-6:GAP-0325
// on Linux and macOS: ensure --config with guardrail.connectors.codex.enabled
// false removes DefenseClaw's Codex machine requirements (journaled as a
// change, idempotent: a second ensure is a no-op), status lists Codex with
// enabled false, and ensure with Codex enabled again puts the requirements
// back. Three cycles, as the live leg runs them.
func TestEnsureWithCodexDisabledTearsDownAndStatusSaysSo(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			file := "linux-standalone.yaml"
			if goos == "darwin" {
				file = "macos-standalone.yaml"
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, readSampleConfig(t, file))}))
			enabled := []byte(h.read(h.env.Layout.ConfigPath))
			if !bytes.Contains(enabled, []byte("    codex: {}\n")) {
				t.Fatalf("the sample config no longer names codex as expected:\n%s", enabled)
			}
			disabled := bytes.Replace(enabled, []byte("    codex: {}\n"), []byte("    codex:\n      enabled: false\n"), 1)
			const requirements = "/etc/codex/requirements.toml"
			hasHooks := func() bool {
				data, err := os.ReadFile(h.env.P(requirements))
				return err == nil && strings.Contains(string(data), "--connector codex")
			}
			if !hasHooks() {
				t.Fatalf("install did not publish the Codex requirements")
			}
			for cycle := 1; cycle <= 3; cycle++ {
				r := h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, disabled)})
				requireOK(t, r)
				if hasHooks() {
					t.Fatalf("cycle %d: %s still runs DefenseClaw's hook with codex disabled", cycle, requirements)
				}
				if _, err := os.Lstat(h.env.P(requirements)); !os.IsNotExist(err) {
					t.Fatalf("cycle %d: %s must be removed (no administrator preimage): %v", cycle, requirements, err)
				}
				if !strings.Contains(strings.Join(r.Changes, "\n"), "removed DefenseClaw's codex machine policy entries") {
					t.Fatalf("cycle %d: the teardown is not reported: %q", cycle, r.Changes)
				}
				if _, ok := r.MachinePolicy["codex"]; ok {
					t.Fatalf("cycle %d: codex still reported in machine policy: %+v", cycle, r.MachinePolicy)
				}
				if again := h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, disabled)}); !again.OK || !again.Noop {
					t.Fatalf("cycle %d: a second disabled ensure must be a no-op: ok=%v noop=%v changes=%q", cycle, again.OK, again.Noop, again.Changes)
				}
				status := h.run(Options{Action: ActionStatus})
				codex, ok := status.Connectors["codex"]
				if !ok || codex.Enabled || codex.ManagedHook != nil {
					t.Fatalf("cycle %d: status must list codex as disabled: %+v (ok=%v)", cycle, codex, ok)
				}
				if claude := status.Connectors["claudecode"]; !claude.Enabled {
					t.Fatalf("cycle %d: claudecode = %+v", cycle, claude)
				}

				r = h.run(Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, enabled)})
				requireOK(t, r)
				if !hasHooks() {
					t.Fatalf("cycle %d: re-enable did not put the Codex requirements back", cycle)
				}
				if status := h.run(Options{Action: ActionStatus}); !status.Connectors["codex"].Enabled {
					t.Fatalf("cycle %d: re-enabled codex = %+v", cycle, status.Connectors["codex"])
				}
			}
		})
	}
}
