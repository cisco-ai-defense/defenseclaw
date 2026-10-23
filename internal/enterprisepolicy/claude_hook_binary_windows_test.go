//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A configured Claude Code drop-in does not protect tool calls when its
// command cannot start. Enrollment and ownership do not change that fact.
func TestWindowsClaudeVerifyRequiresInstalledHookExecutable(t *testing.T) {
	for _, ownership := range []string{"default", config.MachinePolicyOwnershipOff} {
		t.Run(ownership, func(t *testing.T) {
			withHigherSources(t)
			root := t.TempDir()
			hook := filepath.Join(root, "bin", "defenseclaw-hook.exe")
			opts := Options{
				GOOS:                "windows",
				HookBinary:          hook,
				WindowsProgramFiles: filepath.Join(root, "ProgramFiles"),
				WindowsProgramData:  filepath.Join(root, "ProgramData"),
				StateDir:            filepath.Join(root, "state"),
				ClaudeVersionFloor:  config.ClaudeVersionFloorOff,
				SkipTrustChecks:     true,
			}
			if ownership == config.MachinePolicyOwnershipOff {
				opts = withPolicy(opts, ConnectorClaudeCode, func(p *config.EnterpriseConnectorPolicy) {
					p.Ownership = config.MachinePolicyOwnershipOff
				})
			}
			policy, err := renderClaudeDropIn(opts, opts.PolicyFor(ConnectorClaudeCode))
			if err != nil {
				t.Fatal(err)
			}
			path, err := claudeDropInPath(opts)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, string(policy))
			writeFile(t, hook, "installed executable")

			verify := func(wantCovered bool) {
				t.Helper()
				result, err := VerifyAll(opts, []string{ConnectorClaudeCode})
				if err != nil || len(result.States) != 1 {
					t.Fatalf("verify: %+v, %v", result, err)
				}
				state := result.States[0]
				if result.Complete() != wantCovered || state.Covered != wantCovered || state.Route != RouteMachinePolicy {
					t.Fatalf("hook exists=%v: %+v", wantCovered, result)
				}
				if !wantCovered {
					conflicts := strings.Join(state.Conflicts, " ")
					for _, text := range []string{hook, "hook executable", "Stop Claude Code use", "enterprise windows verify --profile standalone --json"} {
						if !strings.Contains(conflicts, text) {
							t.Errorf("conflicts %q do not name %q", conflicts, text)
						}
					}
				}
			}

			verify(true)
			if err := os.Remove(hook); err != nil {
				t.Fatal(err)
			}
			verify(false)
			if err := os.Mkdir(hook, 0o755); err != nil {
				t.Fatal(err)
			}
			verify(false)
			if err := os.Remove(hook); err != nil {
				t.Fatal(err)
			}
			writeFile(t, hook, "")
			verify(false)
			writeFile(t, hook, "restored executable")
			verify(true)
		})
	}
}
