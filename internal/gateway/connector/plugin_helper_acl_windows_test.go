// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// A writable record, hook directory or helper can redirect the plugin's
// bearer-bearing native POST. Exercise the rendered plugins on Windows so
// POSIX mode bits cannot stand in for the actual DACL.
func TestWindowsPerUserPluginRejectsWritableHelperPaths(t *testing.T) {
	node := nodeForTest(t)
	profile, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range []struct{ source, file, function string }{
		{"opencode-plugin.js", "plugin.mjs", "defenseclawPerUserNativePostBinary"},
		{"amp-plugin.ts", "plugin.mts", "perUserNativePostBinary"},
	} {
		for _, hazard := range []struct{ name, target, mutation string }{
			{"record writable", "record", "grant"},
			{"hook directory writable", "hook directory", "grant"},
			{"helper writable", "helper", "grant"},
			{"record wrong owner", "record", "owner"},
			{"hook directory wrong owner", "hook directory", "owner"},
			{"helper wrong owner", "helper", "owner"},
		} {
			t.Run(asset.source+"/"+hazard.name, func(t *testing.T) {
				home, err := os.MkdirTemp(profile, "dc-helper-acl-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(home) })
				hooks := filepath.Join(home, ".defenseclaw", "hooks")
				binDir := filepath.Join(home, ".local", "bin")
				for _, dir := range []string{hooks, binDir} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				record := filepath.Join(hooks, ".gateway-helper")
				binary := filepath.Join(binDir, "defenseclaw-gateway.exe")
				if err := os.WriteFile(binary, []byte("test helper"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(record, []byte(binary+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				// Elevated Windows runners can create files owned by the
				// Administrators group. Give this private fixture the actual
				// account owner that a per-user install has.
				for _, path := range []string{home, filepath.Join(home, ".defenseclaw"), hooks, record,
					filepath.Join(home, ".local"), binDir, binary} {
					if out, err := exec.Command("icacls", path, "/setowner", "*"+current.Uid).CombinedOutput(); err != nil {
						t.Fatalf("set fixture owner: %v\n%s", err, out)
					}
				}
				body := renderPluginAssetForTest(t, asset.source, templateData{TokenFileJS: javaScriptStringContent(filepath.Join(hooks, ".token"))})
				body += "\ntry { " + asset.function + "(); console.log('trusted') } catch (error) { console.log('rejected:' + String(error)) }\n"
				plugin := filepath.Join(home, asset.file)
				if err := os.WriteFile(plugin, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				check := func() string {
					t.Helper()
					out, err := exec.Command(node, plugin).CombinedOutput()
					if err != nil {
						t.Fatalf("rendered plugin: %v\n%s", err, out)
					}
					return strings.TrimSpace(string(out))
				}
				if got := check(); got != "trusted" {
					t.Fatalf("private paths: %q", got)
				}
				target := map[string]string{"record": record, "hook directory": hooks, "helper": binary}[hazard.target]
				args := []string{target, "/grant", "*S-1-5-32-545:W"}
				if hazard.mutation == "owner" {
					args = []string{target, "/setowner", "*S-1-5-32-544"}
				}
				if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
					t.Fatalf("change fixture ACL: %v\n%s", err, out)
				}
				if got := check(); !strings.HasPrefix(got, "rejected:") {
					t.Fatalf("%s: %q", hazard.name, got)
				}
			})
		}
	}
}
