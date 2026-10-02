// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// Devin Desktop starts the agents its ACP registry lists
// (https://docs.devin.ai/desktop/acp): Devin Local is the entry whose
// command is `devin acp`, and any other entry is a third-party agent that
// does not receive Devin hooks. The reporter reads the user's registry and
// reports, without blocking anything:
//   - an agent whose command is not an agent DefenseClaw covers on this
//     host, which runs inside Devin Desktop without DefenseClaw hooks;
//   - a devin entry started with --config, which replaces the user config
//     file (~/.config/devin/config.json, per `devin --help` of Devin CLI
//     3000.11.3) with a file the foreign-hook guard does not check, or with
//     --respect-workspace-trust turned off.
// The registry lives under the pre-rename product folder on macOS and
// Linux and under the Code user folder on Windows, as the vendor documents.

// devinACPRegistryLimit bounds one registry file.
const devinACPRegistryLimit = 1 << 20

// ACPRegistryFinding is one Devin Desktop ACP registry entry the reporter
// flags.
type ACPRegistryFinding struct {
	Path    string `json:"path"`
	Agent   string `json:"agent"`
	Command string `json:"command,omitempty"`
	Reason  string `json:"reason"`
}

// acpAgentConnectors maps an ACP agent command to the connector that
// covers it.
var acpAgentConnectors = map[string]string{
	"devin":        "devin",
	"claude":       ConnectorClaudeCode,
	"codex":        ConnectorCodex,
	"cursor-agent": ConnectorCursor,
	"copilot":      ConnectorCopilot,
	"kiro-cli":     "kiro",
	"opencode":     ConnectorOpenCode,
	"amp":          "amp",
	"hermes":       ConnectorHermes,
}

// DevinACPRegistryPaths returns the user's Devin Desktop ACP registry files.
func DevinACPRegistryPaths(goos, home string) []string {
	if strings.TrimSpace(home) == "" {
		return nil
	}
	if goos == "windows" {
		return []string{filepath.Join(home, "AppData", "Roaming", "Code", "User", "acp", "registry.json")}
	}
	dir := "." + legacyconnector.VendorToken
	return []string{
		filepath.Join(home, dir, "acp", "registry.json"),
		filepath.Join(home, dir+"-next", "acp", "registry.json"),
	}
}

// ScanDevinACPRegistry reports the flagged entries of the user's registry
// files. covered reports whether DefenseClaw covers a connector on this
// host. A registry that cannot be read or parsed is reported as one finding.
func ScanDevinACPRegistry(goos, home string, covered func(connector string) bool) []ACPRegistryFinding {
	var findings []ACPRegistryFinding
	for _, path := range DevinACPRegistryPaths(goos, home) {
		data, exists, err := readGuardFileLimit(path, devinACPRegistryLimit)
		if !exists {
			continue
		}
		if err == nil {
			var found []ACPRegistryFinding
			found, err = parseDevinACPRegistry(path, goos, data, covered)
			findings = append(findings, found...)
		}
		if err != nil {
			findings = append(findings, ACPRegistryFinding{Path: path, Reason: "cannot read the ACP registry: " + err.Error()})
		}
	}
	return findings
}

type acpLaunch struct {
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args"`
	Package string   `json:"package"`
}

type acpRegistry struct {
	Agents []struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Distribution struct {
			Binary map[string]acpLaunch `json:"binary"`
			NPX    *acpLaunch           `json:"npx"`
			UVX    *acpLaunch           `json:"uvx"`
		} `json:"distribution"`
	} `json:"agents"`
}

func parseDevinACPRegistry(path, goos string, data []byte, covered func(string) bool) ([]ACPRegistryFinding, error) {
	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}
	var registry acpRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	platform := map[string]string{"darwin": "darwin-", "linux": "linux-", "windows": "windows-"}[goos]
	var findings []ACPRegistryFinding
	for _, agent := range registry.Agents {
		id := strings.TrimSpace(agent.ID)
		if id == "" {
			id = strings.TrimSpace(agent.Name)
		}
		var launches []acpLaunch
		keys := make([]string, 0, len(agent.Distribution.Binary))
		for key := range agent.Distribution.Binary {
			if platform != "" && strings.HasPrefix(key, platform) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			launches = append(launches, agent.Distribution.Binary[key])
		}
		for _, runner := range []struct {
			cmd    string
			launch *acpLaunch
		}{{"npx", agent.Distribution.NPX}, {"uvx", agent.Distribution.UVX}} {
			if runner.launch != nil {
				launches = append(launches, acpLaunch{Cmd: runner.cmd, Args: append([]string{runner.launch.Package}, runner.launch.Args...)})
			}
		}
		seen := map[string]bool{}
		for _, launch := range launches {
			command := strings.TrimSpace(strings.Join(append([]string{launch.Cmd}, launch.Args...), " "))
			for _, reason := range acpLaunchReasons(launch, covered) {
				if seen[reason] {
					continue
				}
				seen[reason] = true
				findings = append(findings, ACPRegistryFinding{Path: path, Agent: id, Command: command, Reason: reason})
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Agent < findings[j].Agent })
	return findings, nil
}

func acpLaunchReasons(launch acpLaunch, covered func(string) bool) []string {
	base := strings.ToLower(filepath.Base(filepath.FromSlash(strings.ReplaceAll(strings.TrimSpace(launch.Cmd), `\`, "/"))))
	base = strings.TrimSuffix(base, ".exe")
	connector, known := acpAgentConnectors[base]
	if !known || covered == nil || !covered(connector) {
		return []string{"not an agent DefenseClaw covers on this host: Devin Desktop runs it without DefenseClaw hooks"}
	}
	if connector != "devin" {
		return nil
	}
	var reasons []string
	for i, arg := range launch.Args {
		arg = strings.TrimSpace(arg)
		switch {
		case arg == "--config" || strings.HasPrefix(arg, "--config="):
			reasons = append(reasons, "starts Devin Local with --config, which replaces the user config file with one the foreign-hook guard does not check")
		case arg == "--respect-workspace-trust" && i+1 < len(launch.Args) && strings.EqualFold(strings.TrimSpace(launch.Args[i+1]), "false"),
			strings.EqualFold(arg, "--respect-workspace-trust=false"):
			reasons = append(reasons, "starts Devin Local with workspace trust turned off")
		}
	}
	return reasons
}
