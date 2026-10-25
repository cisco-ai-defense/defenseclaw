// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "fmt"

// managedScanGatewayEndpoint: only a managed Windows computer binds the scan
// commands to the managed gateway; elsewhere they use the loaded config.
func managedScanGatewayEndpoint() (string, string, bool, error) {
	return "", "", false, nil
}

// managedScanUnavailable answers `scan skill|mcp|plugin` on a managed Linux
// or macOS computer. Only the managed Windows package ships a scanner
// runtime; the Linux and macOS packages have no skill or MCP scanner, so the
// managed gateway cannot run these scans. They failed with "no per-user
// gateway to check" for root and, past that, with "skill-scanner not found
// ... repair the managed DefenseClaw installation", which no repair fixes
// (GAP-1234). The answer names the scan that does run here, `scan code`,
// which checks a skill's or plugin's files with the CodeGuard rules.
func managedScanUnavailable(kind string) error {
	record, present := managedHostUnixRecord(nil)
	if !present {
		return nil
	}
	gateway := managedHostGatewayCommand()
	scanner, here := "skill", fmt.Sprintf(" To check a %s's files here, an administrator runs `sudo %s scan code <path>`.", kind, gateway)
	switch kind {
	case "mcp":
		scanner = "MCP"
		here = " Add the server through the agent's own MCP configuration (for example `claude mcp add`)."
	case "plugin":
		scanner = "plugin"
	}
	return withExitCode(fmt.Errorf("scan %s: this computer's DefenseClaw is managed by your organization (%s), and the managed Linux and macOS "+
		"packages include no %s scanner, so `scan %s` cannot run here.%s The full %s scan runs on a per-user installation or a managed "+
		"Windows computer. Nothing was scanned", kind, record, scanner, kind, here, scanner), 3)
}
