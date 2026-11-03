// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// The Linux and macOS policy files are written with the Unix file I/O
// (fsio_unix.go), as in the other *_unix_test.go files of this package.

//go:build !windows

package enterprisepolicy

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// disabledCodexConfig is a standalone config whose guardrail.connectors
// names Codex with enabled set as given, next to Claude Code.
func disabledCodexConfig(enabled bool) *config.Config {
	return &config.Config{Guardrail: config.GuardrailConfig{Connectors: map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {},
		"codex":      {Enabled: &enabled},
	}}}
}

// TestDisabledCodexLeavesNoDefenseClawRequirementsOnLinuxAndMacOS is
// rel-1-0-6:GAP-0325: guardrail.connectors.codex.enabled false must take
// DefenseClaw's hooks and lock out of /etc/codex/requirements.toml on Linux
// and macOS, idempotently, and enabling it again must put them back. A file
// the administrator had before DefenseClaw (here one comment line, as on the
// lane's Mac) stays with exactly the administrator's bytes, so nothing in it
// runs DefenseClaw's hook; without one the file is removed.
func TestDisabledCodexLeavesNoDefenseClawRequirementsOnLinuxAndMacOS(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, admin := range []string{"", "\n# admin comment at EOF\n"} {
			name := goos + "/no-preimage"
			if admin != "" {
				name = goos + "/admin-preimage"
			}
			t.Run(name, func(t *testing.T) {
				withHigherSources(t)
				opts := testOptions(t)
				opts.GOOS = goos
				file := codexPath(t, opts)
				if admin != "" {
					writeFile(t, file, admin)
				}
				on, off := disabledCodexConfig(true), disabledCodexConfig(false)
				if got := StandaloneConnectors(off); len(got) != 1 || got[0] != "claudecode" {
					t.Fatalf("StandaloneConnectors(codex enabled: false) = %v, want [claudecode]", got)
				}
				for cycle := 1; cycle <= 3; cycle++ {
					result, err := Publish(opts, StandaloneConnectors(on))
					if err != nil {
						t.Fatalf("cycle %d enable: %v", cycle, err)
					}
					if !containsString(result.MachinePolicyConnectors, "codex") {
						t.Fatalf("cycle %d: codex not in machine policy after enable: %v", cycle, result.MachinePolicyConnectors)
					}
					if text := readFile(t, file); !strings.Contains(text, testHookBinary) || !strings.Contains(text, "allow_managed_hooks_only = true") {
						t.Fatalf("cycle %d: enable did not publish the managed Codex hooks:\n%s", cycle, text)
					}

					result, err = Publish(opts, StandaloneConnectors(off))
					if err != nil {
						t.Fatalf("cycle %d disable: %v", cycle, err)
					}
					if containsString(result.MachinePolicyConnectors, "codex") {
						t.Fatalf("cycle %d: codex still in machine policy after disable: %v", cycle, result.MachinePolicyConnectors)
					}
					if len(result.Retired) != 1 || result.Retired[0].Connector != "codex" || !result.Retired[0].Changed {
						t.Fatalf("cycle %d: disable must retire codex once: %+v", cycle, result.Retired)
					}
					if admin == "" {
						mustNotExist(t, file, "requirements.toml of a disabled Codex DefenseClaw created")
					} else {
						text := readFile(t, file)
						if text != admin || codexHasOwned([]byte(text)) || strings.Contains(text, testHookBinary) {
							t.Fatalf("cycle %d: disable must leave exactly the administrator's file:\n%q", cycle, text)
						}
					}
					again, err := Publish(opts, StandaloneConnectors(off))
					if err != nil || len(again.Retired) != 0 {
						t.Fatalf("cycle %d: a second disable must change nothing: %+v %v", cycle, again.Retired, err)
					}
				}
			})
		}
	}
}
