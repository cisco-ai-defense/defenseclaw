// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1832: a requirements.toml found without the machine policy writer lock
// that holds only administrator text (what an uninstall keeps after GAP-1737,
// or an administrator's own policy on a host DefenseClaw never ran on) is not
// a DefenseClaw managed artifact. Standalone Setup /ensure read it through
// this resolver (prune-orphaned-selectors) and failed 1603 before the fix.
// A file that may carry DefenseClaw content without the lock still fails
// closed: that is a tampered or half-removed install.
func TestGAP1832UnlockedAdministratorRequirementsAreNotManagedArtifacts(t *testing.T) {
	const lockErr = "the Codex managed artifacts exist without the machine policy lock"
	adminComments := "# Contoso Codex policy, owned by IT (ticket 4711).\r\n# Do not edit by hand.\r\n"
	writeRequirements := func(t *testing.T, policyDir string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(policyDir, "requirements.toml"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inactive := map[string]string{
		"comments only, as uninstall leaves them": adminComments,
		"administrator policy and own hook": adminComments + strings.Join([]string{
			`approval_policy_floor = "on-request"`,
			`allow_managed_hooks_only = true`,
			"[features]",
			"hooks = true",
			"[[hooks.PreToolUse]]",
			`matcher = "Bash"`,
			"[[hooks.PreToolUse.hooks]]",
			`type = "command"`,
			`command = 'C:\IT\audit.exe'`,
			"timeout = 5",
			"",
		}, "\n"),
		"empty file": "",
		"administrator policy outside hooks names DefenseClaw": adminComments + "[rules]\ndeny = [\x27defenseclaw uninstall\x27]\n",
	}
	for name, body := range inactive {
		t.Run("inactive: "+name, func(t *testing.T) {
			_, policyDir, hook := newWindowsCodexReaderFixture(t)
			writeRequirements(t, policyDir, []byte(body))
			registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
			if err != nil || registry.Active || len(registry.Targets) != 0 {
				t.Fatalf("administrator-only requirements without the lock = %+v, %v; want inactive (GAP-1832)", registry, err)
			}
		})
	}

	renderFor := func(t *testing.T, hook string) []byte {
		t.Helper()
		opts := standaloneWindowsCodexMachineOptions()
		opts.HookBinary = hook
		opts.ManagedDir = filepath.Dir(hook)
		rendered, changed, err := reconcileWindowsCodexRequirements([]byte(adminComments), opts, false)
		if err != nil || !changed {
			t.Fatalf("render DefenseClaw requirements: changed=%v err=%v", changed, err)
		}
		return rendered
	}
	refused := map[string]func(t *testing.T, hook string) []byte{
		"DefenseClaw tables for this hook": renderFor,
		"DefenseClaw tables of another layout": func(t *testing.T, _ string) []byte {
			return renderFor(t, testWindowsCodexMachineOptions().HookBinary)
		},
		"managed directory only": func(t *testing.T, hook string) []byte {
			return []byte(adminComments + "[hooks]\nwindows_managed_dir = '" + filepath.Dir(hook) + "'\n")
		},
		"administrator group naming the hook image": func(t *testing.T, _ string) []byte {
			return []byte(adminComments + "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = 'D:\\tools\\defenseclaw-hook.exe --diag'\n")
		},
		"encoded command naming DefenseClaw": func(t *testing.T, _ string) []byte {
			command := windowsSystemPowerShellExe() + " -NoLogo -EncodedCommand " + powershellEncodedCommand("& 'E:\\x\\DefenseClaw\\run.cmd'")
			return []byte(adminComments + "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = '" + command + "'\n")
		},
		"unparseable": func(t *testing.T, _ string) []byte {
			return []byte(adminComments + "[hooks\n")
		},
	}
	for name, body := range refused {
		t.Run("refused: "+name, func(t *testing.T) {
			_, policyDir, hook := newWindowsCodexReaderFixture(t)
			writeRequirements(t, policyDir, body(t, hook))
			registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
			if err == nil || !strings.Contains(err.Error(), lockErr) || registry.Active {
				t.Fatalf("possible DefenseClaw requirements without the lock = %+v, %v; want %q", registry, err, lockErr)
			}
		})
	}

	t.Run("refused: state without the lock next to administrator text", func(t *testing.T) {
		_, policyDir, hook := newWindowsCodexReaderFixture(t)
		writeRequirements(t, policyDir, []byte(adminComments))
		if err := os.WriteFile(filepath.Join(policyDir, windowsCodexManagedStateFile), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
		if err == nil || !strings.Contains(err.Error(), lockErr) || registry.Active {
			t.Fatalf("state without the lock = %+v, %v; want %q", registry, err, lockErr)
		}
	})

	// A writer that starts while the unlocked file is read creates its lock
	// first; the reader then reads again against the counter instead of
	// keeping the unlocked verdict.
	t.Run("writer starts during the unlocked read", func(t *testing.T) {
		_, policyDir, hook := newWindowsCodexReaderFixture(t)
		requirements := filepath.Join(policyDir, "requirements.toml")
		writer := filepath.Join(policyDir, WindowsCodexManagedWriterLockFile)
		writeRequirements(t, policyDir, []byte(adminComments))
		windowsCodexMachineTrustedFileCheck = func(path, _ string) error {
			if strings.EqualFold(path, requirements) {
				if _, err := os.Lstat(writer); os.IsNotExist(err) {
					windowsCodexLockSizeForTest(t, writer, 1)
				}
			}
			return nil
		}
		registry, err := ResolveWindowsCodexManagedRuntimeRegistry(hook)
		if err == nil || !strings.Contains(err.Error(), "timed out") || registry.Active {
			t.Fatalf("unlocked read across a new writer = %+v, %v; want it re-read against the counter", registry, err)
		}
	})
}
