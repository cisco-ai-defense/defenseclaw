// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1347: doctor reads the fail_mode field of a per-user script's
// derived-from header (cmd_doctor._derived_hook_header_reason) and compares
// it with the config's outage mode. Every per-user render bakes closed for
// the failures that are not an outage and decides an outage from the config
// at call time, so a fresh script on the default tier (outage open) read as
// "bakes hook fail mode closed; config.yaml says open" and doctor asked the
// user to regenerate the scripts setup had just written. A fresh per-user
// script names no fail mode in its header, whatever the saved mode.
func TestPerUserHookHeaderBakesNoFailMode(t *testing.T) {
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector(), NewHermesConnector(), NewCursorConnector()} {
		for _, mode := range []string{"", "open", "closed"} {
			t.Run(conn.Name()+"/"+mode, func(t *testing.T) {
				data := t.TempDir()
				hookDir := filepath.Join(data, "hooks")
				opts := SetupOpts{DataDir: data, APIAddr: "127.0.0.1:18970", APIToken: "scoped-test-token", HookFailMode: mode}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
				scripts := connectorHookScripts[conn.Name()]
				if len(scripts) == 0 {
					t.Fatalf("no connector script for %s", conn.Name())
				}
				body, err := os.ReadFile(filepath.Join(hookDir, scripts[0]))
				if err != nil {
					t.Fatal(err)
				}
				header := ""
				for _, line := range strings.SplitN(string(body), "\n", 6) {
					if strings.HasPrefix(line, derivedHookHeader) {
						header = line
					}
				}
				if header == "" {
					t.Fatalf("%s has no derived-from header", scripts[0])
				}
				if strings.Contains(header, "fail_mode=") {
					t.Fatalf("%s header bakes a fail mode doctor compares with the outage mode: %q", scripts[0], header)
				}
			})
		}
	}
}
