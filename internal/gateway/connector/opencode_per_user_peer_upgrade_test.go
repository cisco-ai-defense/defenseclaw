// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// An older installed per-user plugin retains the v7 marker but posts directly
// to TCP. Verification must request Setup to replace it before another
// account can hold the gateway port and receive a bearer or tool payload.
func TestOpenCodePerUserUpgradeRejectsOldPluginWithoutPeerGuard(t *testing.T) {
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
		t.Run(release, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			pluginPath := filepath.Join(root, ".config", "opencode", "plugins", "defenseclaw.js")
			oldPath := OpenCodePluginPathOverride
			OpenCodePluginPathOverride = pluginPath
			t.Cleanup(func() { OpenCodePluginPathOverride = oldPath })

			conn := NewOpenCodeConnector()
			opts := prepareOpenCodeSetupOptsForTest(t, SetupOpts{
				DataDir: filepath.Join(root, "defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "scoped-test-token",
			})
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			installed, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			marker := `const DC_PER_USER_NATIVE_POST = "1";`
			if !strings.Contains(string(installed), marker) {
				t.Fatal("per-user OpenCode Setup omitted the native connected-peer guard")
			}
			if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
				t.Fatalf("new guarded plugin did not verify: present=%v err=%v", present, err)
			}

			legacy := strings.Replace(string(installed), marker, `const DC_PER_USER_NATIVE_POST = "";`, 1)
			if release == "0.8.10" {
				legacy = strings.Replace(legacy, "// defenseclaw-managed-plugin v7", "// defenseclaw-managed-plugin v6", 1)
			}
			if err := os.WriteFile(pluginPath, []byte(legacy), 0o600); err != nil {
				t.Fatal(err)
			}
			if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
				t.Fatalf("old unguarded plugin was accepted: present=%v err=%v", present, err)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
				t.Fatalf("Setup did not repair the plugin: present=%v err=%v", present, err)
			}
		})
	}
}

// A standalone Windows plugin uses TCP with a scoped token. A previously
// installed proof followed by a separate POST can send that token to a new
// listener after the gateway releases its port. Setup must repair both
// plugins when verification finds that older transport contract.
func TestManagedPluginUpgradeRejectsSeparateProofAndPost(t *testing.T) {
	for _, tc := range []struct {
		name, pluginName, oldCall, newCall string
	}{
		{"opencode", "defenseclaw.js",
			`if (DC_LISTENER_PROOF) await defenseclawProveListener(token, init.signal);`,
			`if (DC_LISTENER_PROOF) return defenseclawProvenTCPRequest(path, init, token);`},
		{"amp", "defenseclaw.ts",
			`if (DC_LISTENER_PROOF) await proveListener(token, init.signal)`,
			`if (DC_LISTENER_PROOF) return provenTCPRequest(path, init, token)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			pluginPath := filepath.Join(root, ".config", tc.name, "plugins", tc.pluginName)
			var conn Connector
			opts := SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), APIAddr: "127.0.0.1:18970",
				APIToken: "scoped-test-token", ManagedEnterprise: true, ManagedListenerProof: true,
				ForeignHookGuardBinary: testForeignHookGuardBinary()}
			if tc.name == "opencode" {
				old := OpenCodePluginPathOverride
				OpenCodePluginPathOverride = pluginPath
				t.Cleanup(func() { OpenCodePluginPathOverride = old })
				conn = NewOpenCodeConnector()
				opts = prepareOpenCodeSetupOptsForTest(t, opts)
			} else {
				old := AMPPluginPathOverride
				AMPPluginPathOverride = pluginPath
				t.Cleanup(func() { AMPPluginPathOverride = old })
				conn = NewAMPConnector()
				opts = prepareAmpSetupOptsForTest(t, opts)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tc.newCall) {
				t.Fatalf("managed %s Setup lacks the same-connection proof and POST", tc.name)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("new plugin did not verify: present=%v err=%v", present, err)
			}
			legacy := strings.Replace(string(data), tc.newCall, tc.oldCall, 1)
			if err := os.WriteFile(pluginPath, []byte(legacy), 0o600); err != nil {
				t.Fatal(err)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
				t.Fatalf("old separate-proof plugin was accepted: present=%v err=%v", present, err)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("Setup did not repair the plugin: present=%v err=%v", present, err)
			}
		})
	}
}
