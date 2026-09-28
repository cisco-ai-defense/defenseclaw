// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestWindowsEnterpriseManifestUncoveredRows(t *testing.T) {
	yes, no := true, false
	required := []enterprisehooks.ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001", Connector: "codex", UserHome: `C:\Users\a`, AgentVersion: "0.140.0", Enabled: &yes},
		{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", UserHome: `C:\Users\b`, AgentVersion: "2.1.283", Enabled: &yes, Deferred: true},
	}
	installed := []enterprisehooks.ManifestTarget{
		{SID: "s-1-5-21-1-2-3-1001", Connector: "Codex", UserHome: `c:\users\a\`, AgentVersion: "0.140.0"},
		{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", UserHome: `C:\Users\b`, AgentVersion: "2.1.283", Enabled: &yes, Deferred: true},
		// Enumerator-added rows are not drift.
		{SID: "S-1-12-1-1-2-3-4", Connector: "codex", UserHome: `C:\Users\c`, AgentVersion: "0.141.0", Enabled: &yes, Deferred: true},
	}
	if got := windowsEnterpriseManifestUncoveredRows(required, installed); len(got) != 0 {
		t.Fatalf("covered manifest reported drift: %v", got)
	}

	installed[1].Enabled = &no
	installed[0].AgentVersion = "0.139.0"
	want := []string{"S-1-5-21-1-2-3-1001/codex", "S-1-5-21-1-2-3-1002/claudecode"}
	if got := windowsEnterpriseManifestUncoveredRows(required, installed); !reflect.DeepEqual(got, want) {
		t.Fatalf("drift = %v, want %v", got, want)
	}
	if got := windowsEnterpriseManifestUncoveredRows(required, nil); len(got) != 2 {
		t.Fatalf("missing installed manifest must report every required row, got %v", got)
	}
}
