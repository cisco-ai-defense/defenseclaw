// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// nativeDenyConnectors are the connectors without a fail-closed hook contract
// whose per-user hook blocks its own failures with the agent's native deny.
func nativeDenyConnectors() []Connector {
	return []Connector{NewAntigravityConnector(), NewCopilotConnector(), NewHermesConnector()}
}

// A per-user Copilot CLI, Antigravity or Hermes render keeps the resolved
// outage mode. The Windows native hook reads it from .hookcfg, so a closed or
// unset mode must be recorded as closed there, not downgraded to open; the
// outage-open tier is recorded open. Secure Client keeps these connectors
// open (TestManagedStandaloneRenderKeepsClosed).
func TestPerUserNativeDenyRenderRecordsTheResolvedFailMode(t *testing.T) {
	for _, conn := range nativeDenyConnectors() {
		for _, tc := range []struct {
			name, mode, want string
		}{
			{name: "unset", mode: "", want: "closed"},
			{name: "closed", mode: "closed", want: "closed"},
			{name: "outage open tier", mode: "open", want: "open"},
		} {
			t.Run(conn.Name()+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				opts := SetupOpts{
					DataDir:       filepath.Join(dir, "dc"),
					APIAddr:       "127.0.0.1:18970",
					APIToken:      "tok-test",
					HookFailMode:  tc.mode,
					GuardrailMode: "action",
					WorkspaceDir:  dir,
				}
				if got := HookFailClosed(opts, conn); got != (tc.want == "closed") {
					t.Fatalf("HookFailClosed = %v, want %v", got, tc.want == "closed")
				}
				hookDir := filepath.Join(dir, "hooks")
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
				}
				data, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName))
				if err != nil {
					t.Fatalf("read %s: %v", hookConfigSidecarName, err)
				}
				var sidecar struct {
					FailModes map[string]string `json:"fail_modes"`
				}
				if err := json.Unmarshal(data, &sidecar); err != nil {
					t.Fatalf("decode %s: %v", hookConfigSidecarName, err)
				}
				if got := sidecar.FailModes[conn.Name()]; got != tc.want {
					t.Fatalf("%s fail_modes.%s = %q, want %q", hookConfigSidecarName, conn.Name(), got, tc.want)
				}
			})
		}
	}
}
