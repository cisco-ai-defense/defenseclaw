// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

// GAP-2445: a standard account's `enterprise windows discovery --json`
// prints the refusal as JSON on stdout only, with exit 5; cobra's
// "Error: ..." line is left out so merged streams still parse.
func TestWindowsDiscoveryJSONRefusalPrintsOnlyJSON(t *testing.T) {
	original := enterpriseDiscoveryGatewayReport
	t.Cleanup(func() { enterpriseDiscoveryGatewayReport = original })
	enterpriseDiscoveryGatewayReport = func() (enterpriseGatewayAIUsage, string, error) {
		return enterpriseGatewayAIUsage{}, "", withExitCode(&managedViewRefusal{code: "elevation_required", message: "ask your administrator"}, 5)
	}
	for _, args := range [][]string{{"--json"}, {}} {
		var stdout, stderr bytes.Buffer
		command := newWindowsDiscoveryCommand()
		command.SetArgs(args)
		command.SetOut(&stdout)
		command.SetErr(&stderr)
		err := command.Execute()
		if commandExitCode(err) != 5 {
			t.Fatalf("%v: exit %d (%v)", args, commandExitCode(err), err)
		}
		if len(args) == 0 {
			if stdout.Len() != 0 || stderr.String() != "Error: ask your administrator\n" {
				t.Fatalf("text refusal: stdout %q, stderr %q", stdout.String(), stderr.String())
			}
			continue
		}
		var result struct {
			ExitCode int `json:"exit_code"`
		}
		if json.Unmarshal(stdout.Bytes(), &result) != nil || result.ExitCode != 5 || stderr.Len() != 0 {
			t.Fatalf("--json refusal: stdout %q, stderr %q", stdout.String(), stderr.String())
		}
	}
}
