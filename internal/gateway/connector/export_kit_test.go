// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"sort"
	"strings"
)

// The registry views the kit's registry test reads (connector_test,
// gap0545_kit_registry_test.go). They are test-only: no product code needs
// them (substrate-1 GAP-0626).

// ShellTools returns, sorted, the shell tools the registry lists for the
// connector (shellCommandKeys and trustedShellTools), as the tools are named
// to hooks, and the shell tools its hook contracts' golden calls show
// (HookContract.AIDToolCallShapes).
func ShellTools(connectorName string) []string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	seen := map[string]bool{}
	var tools []string
	add := func(tool string) {
		if tool != "" && !seen[tool] {
			seen[tool] = true
			tools = append(tools, tool)
		}
	}
	for tool := range shellCommandKeys[name] {
		add(tool)
	}
	for tool := range trustedShellTools[name] {
		add(tool)
	}
	for _, contract := range KnownHookContracts(name) {
		for _, shape := range contract.AIDToolCallShapes {
			if shape.Surface == ToolSurfaceShell {
				add(shape.Tool)
			}
		}
	}
	sort.Strings(tools)
	return tools
}

// ShellCommandKey is the argument that holds the command of the connector's
// shell tool toolName as the call names it; "" for a tool that is no shell
// tool.
func ShellCommandKey(connectorName, toolName string) string {
	key, _ := shellCommandArgsKey(connectorName, toolName)
	return key
}
