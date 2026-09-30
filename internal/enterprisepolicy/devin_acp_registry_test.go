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
	"strings"
	"testing"
)

// The ACP registry reporter flags third-party agents and Devin Local
// entries that bypass the checked config; a plain Devin Local entry is fine.
func TestDevinACPRegistryReportsUncoveredAgentsAndConfigOverrides(t *testing.T) {
	home := t.TempDir()
	paths := DevinACPRegistryPaths("linux", home)
	writeFile(t, paths[0], `{"version": "1.0.0", "agents": [
		{"id": "devin-cli", "distribution": {"binary": {"linux-x86_64": {"cmd": "devin", "args": ["acp"]}}}},
		{"id": "devin-custom", "distribution": {"binary": {"linux-x86_64": {"cmd": "devin", "args": ["--config", "/tmp/c.json", "acp"]}, "linux-aarch64": {"cmd": "devin", "args": ["--config", "/tmp/c.json", "acp"]}}}},
		{"id": "other", "distribution": {"npx": {"package": "some-acp-agent"}}},
		{"id": "windows-only", "distribution": {"binary": {"windows-x86_64": {"cmd": "other.exe"}}}}
	], "extensions": []}`)
	findings := ScanDevinACPRegistry("linux", home, func(connector string) bool { return connector == "devin" })
	if len(findings) != 2 || findings[0].Agent != "devin-custom" || !strings.Contains(findings[0].Reason, "--config") || findings[1].Agent != "other" {
		t.Fatalf("findings = %+v", findings)
	}
	writeFile(t, paths[1], `{not json`)
	if got := ScanDevinACPRegistry("linux", home, func(string) bool { return true }); len(got) != 3 || !strings.Contains(got[2].Reason, "cannot read") {
		t.Fatalf("an unreadable registry is reported: %+v", got)
	}
}
