// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"strings"
	"testing"
)

// claudeManagedStateRecordBound mirrors windowsClaudeManagedStateLimit in
// internal/enterprisehooks, the bound the managed state record is read under.
// The managed policy is a separate file with its own 4 MiB bound, but it must
// never come near the state bound again: with the guard wrapper written one
// argument to a line it rendered to 105 KB and the managed Windows install
// ended 1603 (GAP-1050).
const claudeManagedStateRecordBound = 64 << 10

func managedWindowsPolicyFor(t *testing.T, contractID, launcher string) []byte {
	t.Helper()
	previous := claudeCodeWindowsHost
	claudeCodeWindowsHost = func() bool { return true }
	t.Cleanup(func() { claudeCodeWindowsHost = previous })
	opts := SetupOpts{
		ManagedEnterprise: true, ClaudeAllowManagedHooksOnly: true,
		HookContractID: contractID, HookExecutable: launcher, DataDir: `C:\ProgramData\DefenseClaw`,
	}
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	hooks, err := renderClaudeCodeManagedHookMatrix(launcher, hookArgs, opts)
	if err != nil {
		t.Fatalf("%s: %v", contractID, err)
	}
	body, err := marshalClaudeCodeManagedPolicy(
		map[string]interface{}{"hooks": hooks, "allowManagedHooksOnly": true},
		claudeCodeManagedPolicyIsCompact(opts),
	)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// The Windows managed policy of the largest Claude Code contract, every hook
// event wrapped by the guard, stays well under the state bound: three quarters
// of it for the default install folder, and seven eighths of it for a folder
// of 150 characters.
func TestManagedClaudeCodeWindowsPolicyStaysWellUnderTheStateBound(t *testing.T) {
	contracts := builtinHookContracts["claudecode"]
	if len(contracts) == 0 {
		t.Fatal("no Claude Code hook contracts")
	}
	long := `C:\Program Files\` + strings.Repeat(`DefenseClaw-long-install-folder-`, 4) + `x\bin`
	for _, tc := range []struct {
		name     string
		folder   string
		maxBytes int
	}{
		{"default install folder", `C:\Program Files\DefenseClaw\bin`, claudeManagedStateRecordBound * 3 / 4},
		{"150 character install folder", long, claudeManagedStateRecordBound * 7 / 8},
	} {
		for _, contract := range contracts {
			body := managedWindowsPolicyFor(t, contract.ContractID, tc.folder+`\defenseclaw-hook.exe`)
			// The size is only meaningful for the guard wrapper form: a handler
			// that fell back to the bare launcher would be small and pass.
			var form struct {
				Hooks map[string][]struct {
					Hooks []struct {
						Command string   `json:"command"`
						Args    []string `json:"args"`
					} `json:"hooks"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(body, &form); err != nil {
				t.Fatalf("%s, %s: %v", tc.name, contract.ContractID, err)
			}
			for event, entries := range form.Hooks {
				if len(entries) != 1 || len(entries[0].Hooks) != 1 ||
					!strings.EqualFold(entries[0].Hooks[0].Command, claudeCodeWindowsCommandProcessor()) ||
					len(entries[0].Hooks[0].Args) < 100 {
					t.Fatalf("%s, %s: %s is not the cmd.exe guard wrapper: %+v", tc.name, contract.ContractID, event, entries)
				}
			}
			if len(body) < 20<<10 {
				t.Fatalf("%s, %s: managed policy is only %d bytes, it cannot hold the guard wrapper of %d events", tc.name, contract.ContractID, len(body), len(contract.Events))
			}
			t.Logf("%s, %s: %d events, %d bytes (state bound %d)", tc.name, contract.ContractID, len(contract.Events), len(body), claudeManagedStateRecordBound)
			if len(body) > tc.maxBytes {
				t.Errorf("%s, %s: managed policy is %d bytes, want at most %d (state bound %d)",
					tc.name, contract.ContractID, len(body), tc.maxBytes, claudeManagedStateRecordBound)
			}
			var parsed struct {
				Hooks map[string][]interface{} `json:"hooks"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Hooks) != len(contract.Events) {
				t.Errorf("%s, %s: policy parses to %d events (err %v), want %d", tc.name, contract.ContractID, len(parsed.Hooks), err, len(contract.Events))
			}
		}
	}
}

// Only the Windows guard wrapper is written compact. Every other managed
// policy, including the Secure Client exec form, keeps the indented bytes.
func TestManagedClaudeCodePolicyIsCompactOnlyForTheWindowsGuardWrapper(t *testing.T) {
	policy := map[string]interface{}{"hooks": map[string]interface{}{"Stop": []interface{}{"a & b > c"}}}
	indented, err := marshalClaudeCodeManagedPolicy(policy, false)
	if err != nil || !strings.Contains(string(indented), "\n  \"hooks\": {\n") || !strings.Contains(string(indented), `\u0026`) {
		t.Fatalf("indented form changed: %q (%v)", indented, err)
	}
	compact, err := marshalClaudeCodeManagedPolicy(policy, true)
	if err != nil || string(compact) != "{\"hooks\":{\"Stop\":[\"a & b > c\"]}}\n" {
		t.Fatalf("compact form: %q (%v)", compact, err)
	}
	previous := claudeCodeWindowsHost
	t.Cleanup(func() { claudeCodeWindowsHost = previous })
	for _, tc := range []struct {
		windows bool
		opts    SetupOpts
		want    bool
	}{
		{true, SetupOpts{ManagedEnterprise: true}, true},
		{true, SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true}, false},
		{true, SetupOpts{}, false},
		{false, SetupOpts{ManagedEnterprise: true}, false},
	} {
		claudeCodeWindowsHost = func() bool { return tc.windows }
		if got := claudeCodeManagedPolicyIsCompact(tc.opts); got != tc.want {
			t.Errorf("windows %v, opts %+v: compact %v, want %v", tc.windows, tc.opts, got, tc.want)
		}
	}
}
