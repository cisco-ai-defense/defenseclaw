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

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1256: an agent started with a DEFENSECLAW_HOME that names no folder (a
// stale export, a typo) while this account's install and gateway run. The
// per-user hook used to treat that as an unavailable home and block every
// call of the session ("hook home unavailable"), plain, with an inherited
// DEFENSECLAW_FAIL_MODE=closed, and under strict availability. The hook now
// keeps the data directory it was installed in and asks its gateway, so the
// gateway's verdict decides in every case, and the missing folder is never
// created.
func TestPerUserHookKeepsItsFolderWhenTheInheritedHomeIsMissing(t *testing.T) {
	gateway, addr := newHookArgvGateway(t)
	for _, conn := range hookArgvShellConnectors {
		conn := conn
		cases := []hookArgvCase{hookArgvConnectorCase(t, conn.Name())}
		if conn.Name() == "claudecode" {
			cases = append(cases, hookArgvInspectCases()[0])
		}
		for _, tc := range cases {
			for _, variant := range []struct {
				name string
				env  []string
			}{
				{"plain", nil},
				{"env-closed", []string{"DEFENSECLAW_FAIL_MODE=closed"}},
				{"strict", []string{"DEFENSECLAW_STRICT_AVAILABILITY=yes"}},
			} {
				t.Run(conn.Name()+"/"+tc.script+"/"+variant.name, func(t *testing.T) {
					data := t.TempDir()
					hookDir := filepath.Join(data, "hooks")
					if err := WriteHookScriptsForConnectorObject(hookDir, addr, "dccert-fake-token-"+conn.Name(), conn); err != nil {
						t.Fatalf("write hooks: %v", err)
					}
					installNativeGatewayForHookTest(t, data, hookDir)
					gateway.take()
					missing := filepath.Join(data, "missing-home")
					env := append([]string{"HOME=" + data, "DEFENSECLAW_HOME=" + missing}, variant.env...)
					code, stdout, stderr := runHookArgvCase(t, hookDir, tc, env)
					requests := gateway.take()
					if strings.Contains(stderr, "hook home unavailable") || code != 0 || len(requests) != 1 {
						t.Fatalf("%s: exit %d, %d gateway requests, want the gateway's allow\nstdout=%s\nstderr=%s",
							tc.script, code, len(requests), stdout, stderr)
					}
					if _, err := os.Stat(missing); !os.IsNotExist(err) {
						t.Fatalf("the hook created the missing DEFENSECLAW_HOME: %v", err)
					}
				})
			}
		}
	}
}

// GAP-1854: a per-user hook installed in a custom DEFENSECLAW_HOME, run by an
// agent that does not pass the variable, took ~/.defenseclaw as its home. An
// unrelated (here disabled) ~/.defenseclaw then decided the call instead of
// the install the hook belongs to, and with no ~/.defenseclaw at all rc.11
// blocked every call as "hook home unavailable". The hook's home is the
// folder it was installed in: it asks its own gateway.
func TestPerUserHookWithoutHomeUsesItsInstalledFolder(t *testing.T) {
	gateway, addr := newHookArgvGateway(t)
	for _, conn := range hookArgvShellConnectors {
		conn := conn
		cases := []hookArgvCase{hookArgvConnectorCase(t, conn.Name())}
		if conn.Name() == "claudecode" {
			cases = append(cases, hookArgvInspectCases()[0])
		}
		for _, tc := range cases {
			t.Run(conn.Name()+"/"+tc.script, func(t *testing.T) {
				root := t.TempDir()
				data := filepath.Join(root, "custom-home")
				hookDir := filepath.Join(data, "hooks")
				if err := WriteHookScriptsForConnectorObject(hookDir, addr, "dccert-fake-token-"+conn.Name(), conn); err != nil {
					t.Fatalf("write hooks: %v", err)
				}
				installNativeGatewayForHookTest(t, data, hookDir)
				user := filepath.Join(root, "user")
				other := filepath.Join(user, ".defenseclaw")
				if err := os.MkdirAll(other, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(other, ".disabled"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				gateway.take()
				code, stdout, stderr := runHookArgvCase(t, hookDir, tc, []string{"HOME=" + user})
				requests := gateway.take()
				if strings.Contains(stderr, "hook home unavailable") || code != 0 || len(requests) != 1 {
					t.Fatalf("%s: exit %d, %d gateway requests, want its own gateway's allow\nstdout=%s\nstderr=%s",
						tc.script, code, len(requests), stdout, stderr)
				}
			})
		}
	}
}
