// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsEnterpriseClaudeRegistryPolicyPath names the Claude Code registry
// policy value.
const windowsEnterpriseClaudeRegistryPolicyPath = `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`

// windowsEnterpriseClaudeRegistryPolicyValue reads the non-empty value of
// HKLM\SOFTWARE\Policies\ClaudeCode\Settings (the 64-bit view), "" when it
// is absent or empty; replaceable in tests.
var windowsEnterpriseClaudeRegistryPolicyValue = func() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\ClaudeCode`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	raw, _, err := key.GetStringValue("Settings")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(raw), nil
}

// windowsEnterpriseStandaloneClaudeRegistryPolicyPreflight refuses, before
// the lifecycle changes anything, a standalone install, ensure, upgrade or
// repair that enrols Claude Code while the Claude Code registry policy holds
// a value that hides DefenseClaw's drop-in (rel-1-0-6:GAP-0409). A value that
// sets managedSourcesBehavior: merge, carries only source-control keys, or
// carries a hooks table that names a DefenseClaw hook or has its hook
// arguments (checked at enrolment) is admitted (GAP-1731, GAP-1801, GAP-2175).
// A hiding value makes Claude Code read it instead of DefenseClaw's
// file-based managed drop-in, so the guardian can never publish
// Claude Code coverage: the lifecycle used to stop after about seven minutes
// with 1603, a pending transaction and the gateway and enumerator stopped,
// and its rollback failed the same way, so every enrolled account failed
// closed until the value was removed. A config that does not enrol Claude
// Code, or one this preflight cannot load (the config preflights report it),
// is not refused here. The Secure Client profile never runs it.
func windowsEnterpriseStandaloneClaudeRegistryPolicyPreflight(configPath string) error {
	connectors, err := windowsEnterpriseStagedConnectors(configPath)
	if err != nil {
		return nil
	}
	enrolsClaude := false
	for _, name := range connectors {
		if strings.EqualFold(strings.TrimSpace(name), "claudecode") {
			enrolsClaude = true
			break
		}
	}
	if !enrolsClaude {
		return nil
	}
	value, err := windowsEnterpriseClaudeRegistryPolicyValue()
	if err != nil || value == "" {
		return nil
	}
	verdict := connector.ClaudeCodeOSAdminPolicyPreflight(value, windowsEnterpriseClaudeRegistryPolicyPath)
	if verdict == nil {
		return nil
	}
	return errors.New("claude_registry_policy: the Claude Code registry policy " + windowsEnterpriseClaudeRegistryPolicyPath +
		" holds a value that Claude Code reads instead of DefenseClaw's managed settings drop-in (" + verdict.Error() + "), so DefenseClaw cannot guard " +
		"Claude Code on this computer, and nothing was changed. Add \"managedSourcesBehavior\": \"merge\" to that value (Claude Code 2.1.242 or later), " +
		"or Delete that registry value (or set it empty), and run the same command again; " +
		"or, if the registry policy must stay, set guardrail.connectors.claudecode.enabled: false in the config you supplied and run the same command again " +
		"(DefenseClaw then does not guard Claude Code)")
}
