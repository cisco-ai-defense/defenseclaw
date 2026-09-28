// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// These helpers bind the HKLM composition check to the release's registered
// Claude contract. The 0.8.6 contract has no DirectoryAdded event.
func claudeCodeHookContractForSetup(opts SetupOpts) (HookContract, error) {
	if pinnedID := strings.TrimSpace(opts.HookContractID); pinnedID != "" {
		contract, ok := hookContractByID("claudecode", pinnedID)
		if !ok {
			return HookContract{}, fmt.Errorf("pinned Claude Code hook contract %q is not registered", pinnedID)
		}
		return contract, nil
	}
	resolution := ResolveHookContract("claudecode", opts.AgentVersion)
	if resolution.Contract.ContractID == "" {
		return HookContract{}, fmt.Errorf("Claude Code version %q does not resolve to a supported hook contract", strings.TrimSpace(opts.AgentVersion))
	}
	return resolution.Contract, nil
}

func claudeCodeHookGroupsForSetup(opts SetupOpts) ([]claudeCodeHookGroup, error) {
	contract, err := claudeCodeHookContractForSetup(opts)
	if err != nil {
		return nil, err
	}
	registry := make(map[string]claudeCodeHookGroup, len(hookGroups))
	for _, group := range hookGroups {
		registry[group.eventType] = group
	}
	groups := make([]claudeCodeHookGroup, 0, len(contract.Events))
	for _, eventType := range contract.Events {
		group, ok := registry[eventType]
		if !ok {
			return nil, fmt.Errorf("Claude Code hook contract %s contains unregistered event %s", contract.ContractID, eventType)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func claudeCodeHandlerTargetsCurrentRuntime(handler map[string]interface{}, opts SetupOpts) bool {
	if hookType, _ := handler["type"].(string); hookType != "command" {
		return false
	}
	if runtime.GOOS == "windows" {
		command, _ := handler["command"].(string)
		expectedCommand := strings.TrimSpace(opts.HookExecutable)
		if expectedCommand == "" {
			expectedCommand = defenseclawHookBinary()
		}
		args, ok := claudeCodeNativeExecArguments(handler)
		if !ok || !pathidentity.Same(command, expectedCommand) {
			return false
		}
		expectedArgs := []string{"hook", "--connector", "claudecode"}
		if opts.ManagedEnterprise && strings.TrimSpace(opts.HookExecutable) != "" {
			expectedArgs = append(expectedArgs, "--enterprise-managed")
		}
		return codexValueMatches(args, expectedArgs)
	}
	command, _ := handler["command"].(string)
	expected := hookInvocationCommand("claudecode", filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")))
	return command == expected
}

func claudeCodeEventTargetsCurrentRuntime(entries []interface{}, opts SetupOpts) bool {
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			continue
		}
		handlers, ok := entry["hooks"].([]interface{})
		if !ok {
			continue
		}
		for _, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]interface{})
			if ok && claudeCodeHandlerTargetsCurrentRuntime(handler, opts) {
				return true
			}
		}
	}
	return false
}
