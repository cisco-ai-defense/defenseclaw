// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
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
// a value (rel-1-0-6:GAP-0409). Claude Code then reads that value instead of
// DefenseClaw's file-based managed drop-in, so the guardian can never publish
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
	return errors.New("claude_registry_policy: the Claude Code registry policy " + windowsEnterpriseClaudeRegistryPolicyPath +
		" holds a value. Claude Code reads that value instead of DefenseClaw's managed settings drop-in, so DefenseClaw cannot guard " +
		"Claude Code on this computer, and nothing was changed. Delete that registry value (or set it empty) and run the same command again; " +
		"or, if the registry policy must stay, set guardrail.connectors.claudecode.enabled: false in the config you supplied and run the same command again " +
		"(DefenseClaw then does not guard Claude Code)")
}
