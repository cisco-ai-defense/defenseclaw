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
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A configured machine policy cannot prove coverage when the executable its
// hook or adapter invokes is gone. No user enrollment is needed for the policy.
func TestWindowsVerifyRequiresInstalledHookExecutable(t *testing.T) {
	for _, connector := range []string{ConnectorClaudeCode, ConnectorCodex, ConnectorCursor, ConnectorCopilot} {
		ownerships := []string{"default", config.MachinePolicyOwnershipOff}
		if connector == ConnectorCopilot {
			ownerships = ownerships[:1] // Copilot ownership off disables its policy.
		}
		for _, ownership := range ownerships {
			t.Run(connector+"/"+ownership, func(t *testing.T) {
				withHigherSources(t)
				root := t.TempDir()
				hook := filepath.Join(root, "bin", "defenseclaw-hook.exe")
				opts := Options{
					GOOS:                 "windows",
					HookBinary:           hook,
					WindowsProgramFiles:  filepath.Join(root, "ProgramFiles"),
					WindowsProgramData:   filepath.Join(root, "ProgramData"),
					StateDir:             filepath.Join(root, "state"),
					ClaudeVersionFloor:   config.ClaudeVersionFloorOff,
					CopilotCLIPolicyOnly: true,
					SkipTrustChecks:      true,
				}
				if ownership == config.MachinePolicyOwnershipOff {
					opts = withPolicy(opts, connector, func(p *config.EnterpriseConnectorPolicy) {
						p.Ownership = config.MachinePolicyOwnershipOff
					})
				}
				var policy []byte
				var path string
				var err error
				switch connector {
				case ConnectorClaudeCode:
					policy, err = renderClaudeDropIn(opts, opts.PolicyFor(connector))
					if err == nil {
						path, err = claudeDropInPath(opts)
					}
				case ConnectorCodex:
					var conflicts []string
					policy, conflicts, err = renderCodex(opts, nil, opts.PolicyFor(connector))
					if len(conflicts) != 0 {
						t.Fatalf("render Codex: %v", conflicts)
					}
					if err == nil {
						path, err = CodexRequirementsPath(opts)
					}
				case ConnectorCursor:
					var adapterPath string
					path, adapterPath, err = windowsCursorPaths(opts)
					if err == nil {
						var adapter []byte
						adapter, err = gatewayconnector.RenderWindowsCursorEnterpriseAdapter(hook, "closed")
						if err == nil {
							policy, err = gatewayconnector.MergeWindowsCursorEnterpriseHooks(nil, adapterPath, "closed")
							if err == nil {
								writeFile(t, adapterPath, string(adapter))
							}
						}
					}
				case ConnectorCopilot:
					policy, err = renderCopilotDropIn(opts)
					if err == nil {
						path, err = copilotDropInPath(opts)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, path, string(policy))
				writeFile(t, hook, "installed executable")

				verify := func(wantCovered bool) {
					t.Helper()
					result, err := VerifyAll(opts, []string{connector})
					if err != nil || len(result.States) != 1 {
						t.Fatalf("verify: %+v, %v", result, err)
					}
					state := result.States[0]
					if result.Complete() != wantCovered || state.Covered != wantCovered || state.Route != RouteMachinePolicy {
						t.Fatalf("hook exists=%v: %+v", wantCovered, result)
					}
					if !wantCovered {
						conflicts := strings.Join(state.Conflicts, " ")
						for _, text := range []string{hook, "hook executable", "Stop " + connectorDisplayName(connector) + " use", "enterprise windows verify --profile standalone --json"} {
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

				// A policy file without the registered hook is still an
				// unguarded agent, even though the executable is present.
				unguarded := `{"hooks":{}}`
				if connector == ConnectorCodex {
					unguarded = "[hooks]\n"
				}
				writeFile(t, path, unguarded)
				result, err := VerifyAll(opts, []string{connector})
				if err != nil || result.Complete() || len(result.States) != 1 || result.States[0].Covered {
					t.Fatalf("unguarded machine policy passed verify: %+v, %v", result, err)
				}
			})
		}
	}
}

func connectorDisplayName(connector string) string {
	switch connector {
	case ConnectorClaudeCode:
		return "Claude Code"
	case ConnectorCodex:
		return "Codex"
	case ConnectorCursor:
		return "Cursor"
	default:
		return "Copilot"
	}
}
