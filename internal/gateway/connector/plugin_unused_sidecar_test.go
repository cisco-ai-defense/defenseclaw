// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Plugin artifacts carry their own fail mode. A damaged shell-hook runtime
// record must not prevent their publication or be rewritten by Setup.
func TestPluginSetupPublishesDespiteUnusableSharedHookRuntimeRecord(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fileName   string
		prepare    func(*testing.T, SetupOpts) SetupOpts
		connector  func() Connector
		setPath    func(string) func()
		failModeJS string
	}{
		{
			name: "opencode", fileName: "defenseclaw.js",
			prepare:   prepareOpenCodeSetupOptsForTest,
			connector: func() Connector { return NewOpenCodeConnector() },
			setPath: func(path string) func() {
				old := OpenCodePluginPathOverride
				OpenCodePluginPathOverride = path
				return func() { OpenCodePluginPathOverride = old }
			},
			failModeJS: `DC_FAIL_MODE = "open"`,
		},
		{
			name: "amp", fileName: "defenseclaw.ts",
			prepare:   prepareAmpSetupOptsForTest,
			connector: func() Connector { return NewAMPConnector() },
			setPath: func(path string) func() {
				old := AMPPluginPathOverride
				AMPPluginPathOverride = path
				return func() { AMPPluginPathOverride = old }
			},
			failModeJS: `DC_FAIL_MODE: string = "open"`,
		},
	} {
		for _, state := range []struct {
			name string
			body string
		}{
			{name: "malformed JSON", body: `{"version":2,"fail_modes":`},
			{name: "unsupported version", body: `{"version":3,"fail_modes":{"codex":"closed"}}`},
		} {
			t.Run(tc.name+"/"+state.name, func(t *testing.T) {
				root := testenv.PrivateTempDir(t)
				pluginPath := filepath.Join(root, ".config", tc.name, "plugins", tc.fileName)
				restorePath := tc.setPath(pluginPath)
				t.Cleanup(restorePath)
				opts := tc.prepare(t, SetupOpts{
					DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970",
					APIToken: "test-token", HookFailMode: "open",
				})
				hookDir := filepath.Join(opts.DataDir, "hooks")
				if err := os.MkdirAll(hookDir, 0o700); err != nil {
					t.Fatal(err)
				}
				sharedPath := filepath.Join(hookDir, ".hookcfg")
				if err := atomicWriteFile(sharedPath, []byte(state.body), 0o600); err != nil {
					t.Fatal(err)
				}
				flatPath := filepath.Join(hookDir, ".hookcfg."+tc.name)
				flatBody := []byte("DEFENSECLAW_CONNECTOR=" + tc.name + "\nDEFENSECLAW_FAIL_MODE=open\n")
				if err := atomicWriteFile(flatPath, flatBody, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := atomicWriteFile(pluginPath, []byte("// previously published plugin\n"), 0o600); err != nil {
					t.Fatal(err)
				}

				var notices bytes.Buffer
				setupErr := func() error {
					previousOutput := log.Writer()
					log.SetOutput(&notices)
					defer log.SetOutput(previousOutput)
					return tc.connector().Setup(context.Background(), opts)
				}()
				if setupErr != nil {
					t.Fatalf("Setup rejected unused shared runtime state: %v", setupErr)
				}
				if got := notices.String(); !strings.Contains(got, tc.name) || !strings.Contains(got, "unused hook runtime record") {
					t.Fatalf("cleanup failure was not reported: %q", got)
				}
				plugin, err := os.ReadFile(pluginPath)
				if err != nil {
					t.Fatalf("read published plugin: %v", err)
				}
				if !bytes.Contains(plugin, []byte(tc.failModeJS)) || bytes.Contains(plugin, []byte("previously published")) {
					t.Fatalf("Setup did not publish the requested %s plugin", tc.name)
				}
				if present, err := OwnedHooksPresent(tc.connector(), opts); err != nil || !present {
					t.Fatalf("gateway would not find the published %s registration: present=%v err=%v", tc.name, present, err)
				}
				for path, want := range map[string][]byte{sharedPath: []byte(state.body), flatPath: flatBody} {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("unused runtime record %s was changed: %q (%v)", path, got, err)
					}
				}
			})
		}
	}
}
