// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func runWindowsClaudePolicyExportForTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newWindowsClaudePolicyExportCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestWindowsClaudePolicyExportIsHiddenAndRegistered(t *testing.T) {
	cmd, _, err := enterpriseWindowsCmd.Find([]string{"export-claude-policy"})
	if err != nil || cmd == nil || cmd.Name() != "export-claude-policy" {
		t.Fatalf("export-claude-policy is not registered under enterprise windows: %v", err)
	}
	if !cmd.Hidden {
		t.Fatal("export-claude-policy must stay hidden")
	}
}

// The exported matrix must be one the enrollment gate accepts inside an
// outranking HKLM policy, for the same hook and contract.
func TestWindowsClaudePolicyExportRoundTripsThroughTheHKLMGate(t *testing.T) {
	hook := filepath.Join(t.TempDir(), "bin", "defenseclaw-hook.exe")
	for _, version := range []string{"2.1.200", "2.1.230"} {
		t.Run(version, func(t *testing.T) {
			out, err := runWindowsClaudePolicyExportForTest(t, "--hook-executable", hook, "--agent-version", version, "--compact")
			if err != nil {
				t.Fatalf("export: %v\n%s", err, out)
			}
			if strings.Count(strings.TrimSpace(out), "\n") != 0 {
				t.Fatalf("--compact printed more than one line: %q", out)
			}
			var exported map[string]interface{}
			if err := json.Unmarshal([]byte(out), &exported); err != nil {
				t.Fatalf("export is not JSON: %v", err)
			}
			if len(exported) != 1 || exported["hooks"] == nil {
				t.Fatalf("export must contain only the hooks matrix, got keys %v", exported)
			}
			if strings.Contains(out, "token") {
				t.Fatal("export leaked credential material")
			}
			hklm, err := json.Marshal(map[string]interface{}{"model": "managed-by-mdm", "hooks": exported["hooks"]})
			if err != nil {
				t.Fatal(err)
			}
			resolution := connector.ResolveHookContract("claudecode", version)
			opts := connector.SetupOpts{
				ManagedEnterprise: true,
				HookFailMode:      "closed",
				HookExecutable:    hook,
				AgentVersion:      version,
				HookContractID:    resolution.Contract.ContractID,
			}
			if err := connector.ClaudeCodeOSAdminPolicyAdmitsManagedHooks(string(hklm), "HKLM Settings", opts); err != nil {
				t.Fatalf("exported matrix was refused by the enrollment gate: %v", err)
			}
		})
	}
}

func TestWindowsClaudePolicyExportDefaultsToTheInstalledHook(t *testing.T) {
	previous := windowsClaudePolicyExportExecutable
	t.Cleanup(func() { windowsClaudePolicyExportExecutable = previous })
	installRoot := t.TempDir()
	windowsClaudePolicyExportExecutable = func() (string, error) {
		return filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe"), nil
	}
	out, err := runWindowsClaudePolicyExportForTest(t)
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	want, _ := json.Marshal(filepath.Join(installRoot, "bin", "defenseclaw-hook.exe"))
	if !strings.Contains(out, string(want)) || !strings.Contains(out, "--enterprise-managed") {
		t.Fatalf("default export does not pin the installed hook %s:\n%s", want, out)
	}

	windowsClaudePolicyExportExecutable = func() (string, error) {
		return filepath.Join(installRoot, "defenseclaw-gateway.exe"), nil
	}
	if _, err := runWindowsClaudePolicyExportForTest(t); err == nil {
		t.Fatal("export outside an installed bin directory guessed a hook path")
	}
}

func TestWindowsClaudePolicyExportRejectsUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	for name, args := range map[string][]string{
		"relative hook":     {"--hook-executable", `bin\defenseclaw-hook.exe`},
		"unclean hook":      {"--hook-executable", root + `\x\..\defenseclaw-hook.exe`},
		"other executable":  {"--hook-executable", filepath.Join(root, "evil.exe")},
		"uncontracted":      {"--hook-executable", filepath.Join(root, "defenseclaw-hook.exe"), "--agent-version", "2.1.153"},
		"positional":        {"--hook-executable", filepath.Join(root, "defenseclaw-hook.exe"), "extra"},
		"malformed version": {"--hook-executable", filepath.Join(root, "defenseclaw-hook.exe"), "--agent-version", "latest"},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := runWindowsClaudePolicyExportForTest(t, args...); err == nil {
				t.Fatalf("export accepted %v:\n%s", args, out)
			}
		})
	}
}
