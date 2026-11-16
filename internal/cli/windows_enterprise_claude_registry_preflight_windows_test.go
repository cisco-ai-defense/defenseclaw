// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0409: a standalone lifecycle that enrols Claude Code while
// HKLM\SOFTWARE\Policies\ClaudeCode\Settings holds a value refuses before
// it changes anything, names the value and says what to do; nothing else is
// refused.
func TestWindowsEnterpriseStandaloneClaudeRegistryPolicyPreflight(t *testing.T) {
	originalConnectors, originalValue := windowsEnterpriseStagedConnectors, windowsEnterpriseClaudeRegistryPolicyValue
	t.Cleanup(func() {
		windowsEnterpriseStagedConnectors, windowsEnterpriseClaudeRegistryPolicyValue = originalConnectors, originalValue
	})
	for _, tc := range []struct {
		name       string
		connectors []string
		loadErr    error
		value      string
		readErr    error
		refused    bool
	}{
		{name: "claude enrolled, value set", connectors: []string{"codex", "claudecode"}, value: `{"env":{"X":"1"}}`, refused: true},
		{name: "claude enrolled, mixed case", connectors: []string{"ClaudeCode"}, value: "{}", refused: true},
		{name: "claude enrolled, no value", connectors: []string{"claudecode"}, value: ""},
		{name: "claude not enrolled, value set", connectors: []string{"codex", "copilot"}, value: `{"env":{}}`},
		{name: "config not loadable", loadErr: errors.New("bad config"), value: "{}"},
		{name: "registry unreadable", connectors: []string{"claudecode"}, readErr: errors.New("access denied")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			windowsEnterpriseStagedConnectors = func(path string) ([]string, error) {
				gotPath = path
				return tc.connectors, tc.loadErr
			}
			windowsEnterpriseClaudeRegistryPolicyValue = func() (string, error) { return tc.value, tc.readErr }
			err := windowsEnterpriseStandaloneClaudeRegistryPolicyPreflight(`C:\stage\config.yaml`)
			if gotPath != `C:\stage\config.yaml` {
				t.Fatalf("config path %q, want the supplied config", gotPath)
			}
			if (err != nil) != tc.refused {
				t.Fatalf("refused=%v err=%v, want refused=%v", err != nil, err, tc.refused)
			}
			if tc.refused {
				for _, want := range []string{
					"claude_registry_policy:",
					`HKLM\SOFTWARE\Policies\ClaudeCode\Settings`,
					"nothing was changed",
					"Delete that registry value",
					"guardrail.connectors.claudecode.enabled: false",
					"run the same command again",
				} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal %q does not say %q", err, want)
					}
				}
				// Setup is not installed on the computer (cowork-1-0-8 GAP-0095).
				if strings.Contains(err.Error(), "Setup") {
					t.Errorf("refusal %q names Setup", err)
				}
			}
		})
	}
}

func TestWindowsEnterpriseLifecycleRunsTheClaudeRegistryPreflightForStandaloneMutationsOnly(t *testing.T) {
	source := readWindowsEnterpriseServiceSourceForTest(t)
	call := strings.Index(source, "windowsEnterpriseStandaloneClaudeRegistryPolicyPreflight(opts.configPath)")
	if call < 0 {
		t.Fatal("the lifecycle does not run the Claude Code registry preflight")
	}
	guard := source[strings.LastIndex(source[:call], "if windowsEnterpriseStandalone(opts)"):call]
	for _, action := range []string{`"install"`, `"ensure"`, `"upgrade"`, `"repair"`} {
		if !strings.Contains(guard, action) {
			t.Errorf("the preflight guard does not cover %s: %s", action, guard)
		}
	}
	if strings.Contains(guard, `"uninstall"`) {
		t.Error("the preflight must not refuse an uninstall")
	}
	if strings.Count(source, "windowsEnterpriseStandaloneClaudeRegistryPolicyPreflight(") != 1 {
		t.Error("the preflight is called more than once")
	}
}

func readWindowsEnterpriseServiceSourceForTest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("windows_enterprise_service.go")
	if err != nil {
		t.Skipf("source not available beside the test binary: %v", err)
	}
	return string(raw)
}
