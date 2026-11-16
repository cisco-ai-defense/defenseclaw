// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A Secure Client plugin cannot send its connector-wide bearer or a tool
// event to an account that replaces the local gateway listener.
func TestSecureClientPluginsKeepHookDataFromAnotherAccountListener(t *testing.T) {
	nodeForTest(t)
	const credential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ asset, scope string }{
		{"opencode-plugin-secure-client.js", "opencode"},
		{"amp-plugin-secure-client.ts", "amp"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.scope+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			seen := &listenerProofRecorder{}
			impostor := newImpostorListener(t, seen)
			verdict := runListenerProofPlugin(t, tc.asset, strings.TrimPrefix(impostor.URL, "http://"), tokenPath, false)
			if !strings.HasPrefix(verdict, "block:") {
				t.Errorf("another account answered with an allow verdict: %q", verdict)
			}
			for _, request := range seen.snapshot() {
				if request.method == http.MethodPost || request.authorization != "" || request.body != "" {
					t.Errorf("another account's listener received a hook credential or event: %+v", request)
				}
			}
		})
	}
}

// The Secure Client guardian must reject a still-versioned plugin written by
// an older release, then Setup must replace it with the service verifier.
func TestSecureClientPluginUpgradeRepairsUnverifiedTCP(t *testing.T) {
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
		for _, tc := range []struct {
			name, file, safeCall, oldCall string
		}{
			{"opencode", "defenseclaw.js", `return defenseclawNativePost(path, init);`, `return fetch("http://" + DC_API_ADDR + path, init);`},
			{"amp", "defenseclaw.ts", `return nativePost(path, init)`, `return fetch("http://" + DC_API_ADDR + path, init)`},
		} {
			t.Run(release+"/"+tc.name, func(t *testing.T) {
				root := testenv.PrivateTempDir(t)
				path := filepath.Join(root, ".config", tc.name, "plugins", tc.file)
				var conn Connector
				opts := SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), APIAddr: "127.0.0.1:18970",
					APIToken: "scoped-test-token", ManagedEnterprise: true,
					HookExecutable: filepath.Join(root, "admin", "defenseclaw-hook")}
				if tc.name == "opencode" {
					old := OpenCodePluginPathOverride
					OpenCodePluginPathOverride = path
					t.Cleanup(func() { OpenCodePluginPathOverride = old })
					conn = NewOpenCodeConnector()
					opts = prepareOpenCodeSetupOptsForTest(t, opts)
				} else {
					old := AMPPluginPathOverride
					AMPPluginPathOverride = path
					t.Cleanup(func() { AMPPluginPathOverride = old })
					conn = NewAMPConnector()
					opts = prepareAmpSetupOptsForTest(t, opts)
				}
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				installed, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(installed), tc.safeCall) {
					t.Fatal("Secure Client Setup did not render native service verification")
				}
				legacy := strings.Replace(string(installed), tc.safeCall, tc.oldCall, 1)
				if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
					t.Fatalf("old unverified plugin from %s was accepted: present=%v err=%v", release, present, err)
				}
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
					t.Fatalf("Setup did not repair the old plugin: present=%v err=%v", present, err)
				}
			})
		}
	}
}

func TestSecureClientPluginsSendOnlyThroughTheNativeServiceVerifier(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the native verifier fixture is a Unix executable; Windows uses its installed hook binary")
	}
	nodeForTest(t)
	const credential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ asset, scope string }{
		{"opencode-plugin-secure-client.js", "opencode"},
		{"amp-plugin-secure-client.ts", "amp"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.scope+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(root, "native-input.json")
			argsPath := filepath.Join(root, "native-args.txt")
			t.Setenv("DC_TEST_NATIVE_INPUT", inputPath)
			t.Setenv("DC_TEST_NATIVE_ARGS", argsPath)
			binary := filepath.Join(root, "native-verifier")
			stub := "#!/bin/sh\ncat > \"$DC_TEST_NATIVE_INPUT\"\nprintf '%s\\n' \"$@\" > \"$DC_TEST_NATIVE_ARGS\"\nprintf '%s\\n' '{\"status\":200,\"body\":\"{\\\"action\\\":\\\"allow\\\",\\\"hook_output\\\":{\\\"decision\\\":\\\"allow\\\"}}\"}'\n"
			if err := os.WriteFile(binary, []byte(stub), 0o700); err != nil {
				t.Fatal(err)
			}
			harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
			if tc.scope == "amp" {
				harness, name = ampListenerProofHarness, "amp-plugin.mts"
			}
			plugin := writeRenderedPlugin(t, tc.asset, name, templateData{
				APIAddr: "127.0.0.1:18970", TokenFileJS: javaScriptStringContent(tokenPath),
				NativePostBinaryJS: javaScriptStringContent(binary), FailMode: "closed", Managed: true,
			})
			verdict := strings.Join(runNodeHarness(t, harness, plugin), "\n")
			if verdict != "allow" {
				t.Fatalf("native verified reply = %q", verdict)
			}
			input, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			args, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(input), "Bearer "+credential) ||
				!strings.Contains(string(input), "listener-proof-marker") ||
				strings.Contains(string(args), credential) ||
				!strings.Contains(string(args), "--secure-client-service") {
				t.Fatalf("native verifier did not carry the credential and event on stdin only")
			}
		})
	}
}
