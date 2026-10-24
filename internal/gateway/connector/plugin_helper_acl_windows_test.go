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
// POSIX mode bits cannot stand in for the actual DACL. A real install is
// trusted: a per-user install (owned by the user, under a SYSTEM-owned
// profile), an elevated one (owned by Administrators), OS-owned parents
// (TrustedInstaller) and inherit-only entries that do not apply to the path
// itself. A path another principal owns or may write is rejected, including
// a parent of a data directory nested inside the profile. Every folder above
// the checked paths up to the volume root is checked for the rights that let
// another principal rename or replace it (delete, delete-child, change
// permissions, take ownership): a custom data root that holds the helper has
// no checked parent otherwise, and swapping it after the check hands the
// bearer to a planted helper. Create-folder rights (as C:\ grants Users)
// are not such a right.
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
	// Another local account (the built-in Guest, RID 501) of this machine.
	otherUser := current.Uid[:strings.LastIndex(current.Uid, "-")] + "-501"
	const (
		users          = "*S-1-5-32-545"
		everyone       = "*S-1-1-0"
		system         = "*S-1-5-18"
		administrators = "*S-1-5-32-544"
		trustedInstall = "NT SERVICE\\TrustedInstaller"
	)
	type layout struct{ grand, parent, home, nest, data, hooks, record, binDir, binary string }
	for _, asset := range []struct{ source, file, function string }{
		{"opencode-plugin.js", "plugin.mjs", "defenseclawPerUserNativePostBinary"},
		{"amp-plugin.ts", "plugin.mts", "perUserNativePostBinary"},
	} {
		for _, tc := range []struct {
			name    string
			nested  bool
			custom  bool   // a custom data root that holds the helper (home = data root)
			owner   string // owner of every fixture path; "" = the current user
			changes func(l layout) [][]string
			trusted bool
		}{
			{name: "per-user install", trusted: true},
			{name: "per-user install under a SYSTEM-owned profile", trusted: true,
				changes: func(l layout) [][]string { return [][]string{{l.home, "/setowner", system}} }},
			{name: "elevated install owned by Administrators", owner: administrators, trusted: true},
			{name: "TrustedInstaller-owned bin directory", trusted: true,
				changes: func(l layout) [][]string { return [][]string{{l.binDir, "/setowner", trustedInstall}} }},
			{name: "inherit-only grant on the bin directory", trusted: true,
				changes: func(l layout) [][]string { return [][]string{{l.binDir, "/grant", users + ":(CI)(IO)W"}} }},
			{name: "nested data directory", nested: true, trusted: true},
			{name: "record writable by Users",
				changes: func(l layout) [][]string { return [][]string{{l.record, "/grant", users + ":W"}} }},
			{name: "hook directory writable by Users",
				changes: func(l layout) [][]string { return [][]string{{l.hooks, "/grant", users + ":W"}} }},
			{name: "planted helper writable by Users",
				changes: func(l layout) [][]string { return [][]string{{l.binary, "/grant", users + ":W"}} }},
			{name: "planted helper modifiable by Everyone",
				changes: func(l layout) [][]string { return [][]string{{l.binary, "/grant", everyone + ":M"}} }},
			{name: "planted helper writable by another user",
				changes: func(l layout) [][]string { return [][]string{{l.binary, "/grant", "*" + otherUser + ":W"}} }},
			{name: "bin directory writable by Users",
				changes: func(l layout) [][]string { return [][]string{{l.binDir, "/grant", users + ":W"}} }},
			{name: "nested data parent writable by Users", nested: true,
				changes: func(l layout) [][]string { return [][]string{{l.nest, "/grant", users + ":W"}} }},
			{name: "record owned by Users",
				changes: func(l layout) [][]string { return [][]string{{l.record, "/setowner", users}} }},
			{name: "hook directory owned by another user",
				changes: func(l layout) [][]string { return [][]string{{l.hooks, "/setowner", "*" + otherUser}} }},
			{name: "helper owned by Users",
				changes: func(l layout) [][]string { return [][]string{{l.binary, "/setowner", users}} }},
			{name: "custom data root holding the helper", custom: true, trusted: true},
			{name: "elevated custom data root owned by Administrators", custom: true, owner: administrators, trusted: true},
			{name: "custom data root parent where Users may create folders", custom: true, trusted: true,
				changes: func(l layout) [][]string { return [][]string{{l.parent, "/grant", users + ":(AD)"}} }},
			{name: "parent swap: custom data root parent modifiable by Users", custom: true,
				changes: func(l layout) [][]string { return [][]string{{l.parent, "/grant", users + ":M"}} }},
			{name: "parent swap: custom data root parent grants Users delete-child", custom: true,
				changes: func(l layout) [][]string { return [][]string{{l.parent, "/grant", users + ":(DC)"}} }},
			{name: "parent swap: custom data root parent permissions changeable by Users", custom: true,
				changes: func(l layout) [][]string { return [][]string{{l.parent, "/grant", users + ":(WDAC)"}} }},
			{name: "parent swap: custom data root grandparent under Everyone full control", custom: true,
				changes: func(l layout) [][]string { return [][]string{{l.grand, "/grant", everyone + ":F"}} }},
			{name: "parent swap: custom data root parent owned by another user", custom: true,
				changes: func(l layout) [][]string { return [][]string{{l.parent, "/setowner", "*" + otherUser}} }},
		} {
			t.Run(asset.source+"/"+tc.name, func(t *testing.T) {
				base, err := os.MkdirTemp(profile, "dc-helper-acl-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(base) })
				l := layout{grand: base, parent: filepath.Join(base, "parent"), home: base, nest: base}
				if tc.nested {
					l.nest = filepath.Join(base, "nest")
				}
				l.data = filepath.Join(l.nest, ".defenseclaw")
				if tc.custom {
					// The layout setup records when a custom data root holds
					// the gateway: <root>\.local\bin under the root itself.
					l.home = filepath.Join(l.parent, "dcroot")
					l.nest, l.data = l.home, l.home
				}
				home := l.home
				l.binDir = filepath.Join(home, ".local", "bin")
				l.hooks = filepath.Join(l.data, "hooks")
				l.record = filepath.Join(l.hooks, ".gateway-helper")
				l.binary = filepath.Join(l.binDir, "defenseclaw-gateway.exe")
				for _, dir := range []string{l.parent, l.hooks, l.binDir} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(l.binary, []byte("test helper"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(l.record, []byte(l.binary+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				owner := tc.owner
				if owner == "" {
					owner = "*" + current.Uid
				}
				icacls := func(args ...string) {
					t.Helper()
					if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
						t.Fatalf("icacls %v: %v\n%s", args, err, out)
					}
				}
				// Elevated Windows runners create files owned by the
				// Administrators group; give each fixture its install's owner.
				for _, path := range []string{base, l.parent, home, l.nest, l.data, l.hooks, l.record,
					filepath.Join(home, ".local"), l.binDir, l.binary} {
					icacls(path, "/setowner", owner)
				}
				body := renderPluginAssetForTest(t, asset.source, templateData{TokenFileJS: javaScriptStringContent(filepath.Join(l.hooks, ".token"))})
				body += "\ntry { " + asset.function + "(); console.log('trusted') } catch (error) { console.log('rejected:' + String(error)) }\n"
				plugin := filepath.Join(base, asset.file)
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
					t.Fatalf("private fixture: %q", got)
				}
				if tc.changes != nil {
					for _, args := range tc.changes(l) {
						icacls(args...)
					}
				}
				got := check()
				if tc.trusted && got != "trusted" {
					t.Fatalf("%s: %q, want trusted", tc.name, got)
				}
				if !tc.trusted && !strings.HasPrefix(got, "rejected:") {
					t.Fatalf("%s: %q, want rejected", tc.name, got)
				}
			})
		}
	}
}
