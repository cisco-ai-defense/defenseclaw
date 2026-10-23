//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The build host's own machine-wide agents must not leak into the scan's
// results; a test that needs machine prefixes sets them.
func init() { privateInstallMachinePrefixes = func() []string { return nil } }

func withPrivateInstallMachinePrefixes(t *testing.T, prefixes ...string) {
	t.Helper()
	previous := privateInstallMachinePrefixes
	privateInstallMachinePrefixes = func() []string { return prefixes }
	t.Cleanup(func() { privateInstallMachinePrefixes = previous })
}

// machineTestDir is a directory outside the test homes whose every
// ancestor refuses group and other writes, as a root-owned machine prefix
// does: the working tree when its chain allows, else a directory below the
// test user's own home directory.
func machineTestDir(t *testing.T) string {
	t.Helper()
	ownerOnly := func(dir string) bool {
		for ancestor := dir; ; ancestor = filepath.Dir(ancestor) {
			if info, err := os.Stat(ancestor); err != nil || info.Mode().Perm()&0o022 != 0 {
				return false
			}
			if ancestor == filepath.Dir(ancestor) {
				return true
			}
		}
	}
	if dir := trustedTestDir(t); ownerOnly(filepath.Dir(dir)) {
		return dir
	}
	base, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no owner-only directory chain for machine prefixes: %v", err)
	}
	dir, err := os.MkdirTemp(base, ".dc-machine-test-")
	if err != nil {
		t.Skipf("no owner-only directory chain for machine prefixes: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil || !ownerOnly(dir) {
		t.Skipf("no owner-only directory chain for machine prefixes (%s)", dir)
	}
	return dir
}

func withExtendedUnixDiscovery(t *testing.T) {
	t.Helper()
	previous := unixUserDiscoveryExtended
	unixUserDiscoveryExtended = func() bool { return true } // the managed per-user worker
	t.Cleanup(func() { unixUserDiscoveryExtended = previous })
}

// npmCopy writes an npm package below prefix/<modules>. entry is the
// runnable file it holds ("" for none: a leftover package record).
func npmCopy(t *testing.T, dir, pkg, version, entry string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"`+pkg+`","version":"`+version+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if entry != "" {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, entry)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func claudePackage(root string, lib bool) string {
	if lib {
		return filepath.Join(root, "lib", "node_modules", "@anthropic-ai", "claude-code")
	}
	return filepath.Join(root, "node_modules", "@anthropic-ai", "claude-code")
}

// installFacts reads a finding through its JSON form, as the root parent
// receives it from the worker.
func installFacts(t *testing.T, install PrivateAgentInstall) map[string]any {
	t.Helper()
	data, err := json.Marshal(install)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]any{}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func describeInstalls(t *testing.T, found []PrivateAgentInstall, home string) []string {
	t.Helper()
	var out []string
	for _, install := range found {
		facts := installFacts(t, install)
		switch {
		case install.Incomplete:
			skipped, _ := facts["skipped"].(string)
			out = append(out, install.Connector+" incomplete "+skipped)
		case facts["untrusted"] == true:
			out = append(out, install.Connector+" untrusted "+strings.TrimPrefix(install.Path, home))
		default:
			out = append(out, install.Connector+" "+install.Version+" "+strings.TrimPrefix(install.Path, home))
		}
	}
	sort.Strings(out)
	return out
}

// Every copy an enrolled account can run is judged once, by its real path,
// wherever it was installed: per-user and machine npm, the native npm
// entry point, version managers without truncation, native installers and
// Homebrew casks (GAP-0890, GAP-0891, GAP-0892). A supported copy never
// hides an older one, and a supported install alone reports nothing.
func TestDiscoverUnixPrivateInstallsCoverEveryCopyLayout(t *testing.T) {
	type layout struct {
		home, machineA, machineB string
	}
	cases := []struct {
		name  string
		build func(t *testing.T, l layout)
		want  []string
	}{
		{
			name: "healthy: supported native npm, machine and cask copies report nothing",
			build: func(t *testing.T, l layout) {
				npmCopy(t, claudePackage(filepath.Join(l.home, ".npm-global"), true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
				npmCopy(t, claudePackage(l.machineA, true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
				cask := filepath.Join(l.machineA, "Caskroom", "claude-code", "2.1.230")
				npmCopy(t, cask, "unused", "0", "claude")
			},
		},
		{
			name: "old native npm entry point without cli.js (GAP-0890)",
			build: func(t *testing.T, l layout) {
				npmCopy(t, claudePackage(filepath.Join(l.home, ".npm-global"), true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
				npmCopy(t, claudePackage(filepath.Join(l.home, "private"), false), "@anthropic-ai/claude-code", "2.1.150", "bin/claude.exe")
			},
			want: []string{"claudecode 2.1.150 /private/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "package record without an entry point is a leftover, not a copy",
			build: func(t *testing.T, l layout) {
				npmCopy(t, claudePackage(filepath.Join(l.home, "private"), false), "@anthropic-ai/claude-code", "2.0.77", "")
			},
		},
		{
			name: "old copy in a second machine prefix beside a supported one (GAP-0891)",
			build: func(t *testing.T, l layout) {
				npmCopy(t, claudePackage(l.machineA, true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
				npmCopy(t, claudePackage(l.machineB, true), "@anthropic-ai/claude-code", "2.0.77", "cli.js")
				npmCopy(t, filepath.Join(l.machineB, "lib", "node_modules", "@openai", "codex"), "@openai/codex", "0.0.1", "bin/codex.js")
			},
			want: []string{"claudecode 2.0.77 MACHINE-B/lib/node_modules/@anthropic-ai/claude-code", "codex 0.0.1 MACHINE-B/lib/node_modules/@openai/codex"},
		},
		{
			name: "machine copy another account can change is unverified whatever it claims",
			build: func(t *testing.T, l layout) {
				dir := npmCopy(t, claudePackage(l.machineB, true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"claudecode untrusted MACHINE-B/lib/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "one copy reached through a linked directory and a linked prefix is one copy",
			build: func(t *testing.T, l layout) {
				npmCopy(t, claudePackage(filepath.Join(l.home, "private"), false), "@anthropic-ai/claude-code", "2.0.77", "cli.js")
				if err := os.Symlink(filepath.Join(l.home, "private"), filepath.Join(l.home, "alias")); err != nil {
					t.Fatal(err)
				}
				npmCopy(t, claudePackage(l.machineA, true), "@anthropic-ai/claude-code", "2.0.76", "cli.js")
				if err := os.RemoveAll(l.machineB); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(l.machineA, l.machineB); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"claudecode 2.0.76 MACHINE-A/lib/node_modules/@anthropic-ai/claude-code", "claudecode 2.0.77 /private/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "old copy in the 17th of 17 nvm Node versions (GAP-0892)",
			build: func(t *testing.T, l layout) {
				for minor := 0; minor < 17; minor++ {
					prefix := filepath.Join(l.home, ".nvm", "versions", "node", fmt.Sprintf("v20.%d.0", minor))
					version, entry := "2.1.230", "bin/claude.exe"
					if minor == 0 {
						version, entry = "2.0.77", "cli.js"
					}
					npmCopy(t, claudePackage(prefix, true), "@anthropic-ai/claude-code", version, entry)
				}
			},
			want: []string{"claudecode 2.0.77 /.nvm/versions/node/v20.0.0/lib/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "more Node versions than the scan bound is reported incomplete, not dropped",
			build: func(t *testing.T, l layout) {
				for minor := 0; minor <= privateAgentInstallMaxVersionDirs; minor++ {
					if err := os.MkdirAll(filepath.Join(l.home, ".local", "share", "fnm", "node-versions", fmt.Sprintf("v18.%d.0", minor), "installation"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: []string{"claudecode incomplete " + PrivateInstallSkippedVersionManagers, "codex incomplete " + PrivateInstallSkippedVersionManagers},
		},
		{
			name: "old Homebrew cask releases of Claude Code and Codex",
			build: func(t *testing.T, l layout) {
				npmCopy(t, filepath.Join(l.machineA, "Caskroom", "claude-code", "2.0.77"), "unused", "0", "claude")
				npmCopy(t, filepath.Join(l.machineA, "Caskroom", "claude-code", "2.1.230"), "unused", "0", "claude")
				if err := os.MkdirAll(filepath.Join(l.machineA, "Caskroom", "claude-code", ".metadata"), 0o755); err != nil {
					t.Fatal(err)
				}
				npmCopy(t, filepath.Join(l.machineA, "Caskroom", "codex", "0.0.1"), "unused", "0", "codex-aarch64-apple-darwin")
			},
			want: []string{"claudecode 2.0.77 MACHINE-A/Caskroom/claude-code/2.0.77", "codex 0.0.1 MACHINE-A/Caskroom/codex/0.0.1"},
		},
		{
			name: "more native releases than the bound is reported incomplete",
			build: func(t *testing.T, l layout) {
				dir := filepath.Join(l.home, ".local", "share", "claude", "versions")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for patch := 0; patch <= privateAgentInstallMaxVersionDirs; patch++ {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("2.1.%d", 300+patch)), []byte("native"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: []string{"claudecode incomplete " + PrivateInstallSkippedNativeVersions},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withExtendedUnixDiscovery(t)
			machine := machineTestDir(t)
			l := layout{home: makeHome(t, trustedTestDir(t), "alice"), machineA: filepath.Join(machine, "machine-a"), machineB: filepath.Join(machine, "machine-b")}
			for _, dir := range []string{l.machineA, l.machineB} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			withPrivateInstallMachinePrefixes(t, l.machineA, l.machineB)
			tc.build(t, l)
			var got []string
			for _, line := range describeInstalls(t, DiscoverUnixPrivateAgentInstalls(l.home, []string{"claudecode", "codex"}), l.home) {
				line = strings.ReplaceAll(line, "/alias/", "/private/") // one copy, whichever name the listing meets first
				line = strings.ReplaceAll(line, l.machineA, "MACHINE-A")
				got = append(got, strings.ReplaceAll(line, l.machineB, "MACHINE-B"))
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("copies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// A Codex or Copilot package folder counts as a copy only when it holds a
// file the account can start: the vendor's entry point or a target of its
// package.json "bin". Metadata alone is a leftover and keeps a healthy
// install healthy; a runnable copy without metadata is still reported, and
// an entry point that cannot be read leaves the scan incomplete.
func TestDiscoverUnixPrivateNPMCopiesNeedAnEntryPoint(t *testing.T) {
	packages := map[string]string{"codex": "@openai/codex", "copilot": "@github/copilot"}
	// The vendors' entry points: Codex bin/codex.js, Copilot npm-loader.js
	// (index.js in early releases).
	entries := map[string][]string{"codex": {"bin/codex.js"}, "copilot": {"npm-loader.js", "index.js"}}
	for _, tc := range []struct {
		name     string
		build    func(t *testing.T, dir, connector, pkg string)
		reported bool
		skipped  string
	}{
		{name: "metadata only", build: func(t *testing.T, dir, _, pkg string) {
			npmCopy(t, dir, pkg, "0.0.1", "")
		}},
		{name: "bin names a missing file", build: func(t *testing.T, dir, connector, pkg string) {
			writeNPMManifest(t, dir, `{"name":"`+pkg+`","version":"0.0.1","bin":{"`+connector+`":"bin/missing.js"}}`)
		}},
		{name: "bin escapes the package", build: func(t *testing.T, dir, connector, pkg string) {
			npmCopy(t, filepath.Join(filepath.Dir(dir), "outside"), "outside", "1.0.0", "run.js")
			writeNPMManifest(t, dir, `{"name":"`+pkg+`","version":"0.0.1","bin":"../outside/run.js"}`)
		}},
		{name: "vendor entry point", build: func(t *testing.T, dir, connector, pkg string) {
			npmCopy(t, dir, pkg, "0.0.1", entries[connector][0])
		}, reported: true},
		{name: "early entry point", build: func(t *testing.T, dir, connector, pkg string) {
			npmCopy(t, dir, pkg, "0.0.1", entries[connector][len(entries[connector])-1])
		}, reported: true},
		{name: "bin target the package names", build: func(t *testing.T, dir, connector, pkg string) {
			npmCopy(t, dir, pkg, "0.0.1", "dist/main.js")
			writeNPMManifest(t, dir, `{"name":"`+pkg+`","version":"0.0.1","bin":{"`+connector+`":"./dist/main.js"}}`)
		}, reported: true},
		{name: "entry point without metadata", build: func(t *testing.T, dir, connector, pkg string) {
			npmCopy(t, dir, pkg, "0.0.1", entries[connector][0])
			if err := os.Remove(filepath.Join(dir, "package.json")); err != nil {
				t.Fatal(err)
			}
		}, reported: true},
		{name: "unreadable entry point", build: func(t *testing.T, dir, connector, pkg string) {
			writeNPMManifest(t, dir, `{"name":"`+pkg+`","version":"0.0.1","bin":"`+strings.Repeat("x", 300)+`.js"}`)
		}, skipped: PrivateInstallSkippedLocation},
		{name: "unreadable metadata", build: func(t *testing.T, dir, _, _ string) {
			if err := os.MkdirAll(filepath.Join(dir, "package.json"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, skipped: PrivateInstallSkippedLocation},
	} {
		for connector, pkg := range packages {
			t.Run(tc.name+"/"+connector, func(t *testing.T) {
				home := makeHome(t, trustedTestDir(t), "alice")
				dir := filepath.Join(home, "private", "node_modules", filepath.FromSlash(pkg))
				tc.build(t, dir, connector, pkg)
				found := DiscoverUnixPrivateAgentInstalls(home, []string{connector})
				switch {
				case tc.skipped != "":
					if len(found) != 1 || !found[0].Incomplete || found[0].Skipped != tc.skipped {
						t.Fatalf("findings = %+v, want one incomplete %s", found, tc.skipped)
					}
				case tc.reported:
					if len(found) != 1 || found[0].Incomplete || found[0].Path != dir {
						t.Fatalf("findings = %+v, want the copy at %s", found, dir)
					}
				case len(found) != 0:
					t.Fatalf("leftover package reported: %+v", found)
				}
			})
		}
	}
}

func writeNPMManifest(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// More copies than the record holds marks the scan incomplete.
func TestDiscoverUnixPrivateInstallsReportsTheFindingLimit(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	for i := 0; i <= privateAgentInstallMaxFindings; i++ {
		npmCopy(t, claudePackage(filepath.Join(home, fmt.Sprintf("old-%02d", i)), false), "@anthropic-ai/claude-code", "2.0.77", "cli.js")
	}
	found := DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode"})
	last := found[len(found)-1]
	if len(found) != privateAgentInstallMaxFindings+1 || !last.Incomplete || installFacts(t, last)["skipped"] != PrivateInstallSkippedFindings {
		t.Fatalf("%d findings, last %+v", len(found), last)
	}
}

// The worker's machine-prefix findings pass the parent's path check; a
// path anywhere else does not.
func TestUnixPrivateInstallPathAllowedNamesTheScanRoots(t *testing.T) {
	withPrivateInstallMachinePrefixes(t, "/usr/local", "/usr")
	for path, want := range map[string]bool{
		"/home/alice/private/node_modules/@anthropic-ai/claude-code": true,
		"/usr/lib/node_modules/@anthropic-ai/claude-code":            true,
		"/usr/local/Caskroom/claude-code/2.0.77":                     true,
		"/home/linuxbrew/.linuxbrew/lib/node_modules/@openai/codex":  true,
		"/etc/shadow":                    false,
		"/home/bob/private/node_modules": false,
		"/home/alice/../bob/x":           false,
	} {
		if got := UnixPrivateInstallPathAllowed("/home/alice", filepath.Clean(path)); got != want {
			t.Errorf("%s allowed = %t, want %t", path, got, want)
		}
	}
}

// Manifest enrollment inspects the administrator's enabled targets, even
// ones outside the automatic filters, and no one else; a target the cycle
// cannot inspect is incomplete, and exclusions still win (GAP-0906).
func TestEnumerateUnixManifestModeInspectsTheAuthoredTargets(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	account := func(name string) unixidentity.Account {
		return unixidentity.Account{Name: name, UID: uid, GID: gid, Home: makeHome(t, homes, name), Shell: "/bin/bash"}
	}
	// svc's uid is below the automatic range and its shell is nologin, but
	// the administrator authored it.
	svc := account("svc")
	svc.Shell = "/usr/sbin/nologin"
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
		"svc": svc, "bob": account("bob"), "carol": account("carol"), "erin": account("erin"),
	}, transient: map[string]bool{"dave": true}, listed: []string{"svc", "bob", "carol", "erin"}}
	enabled, disabled := true, false
	row := func(user string, on *bool) ManifestTarget {
		home := filepath.Join(homes, user)
		return ManifestTarget{User: user, UserHome: home, UID: intPointer(uid), GID: intPointer(gid), Connector: "claudecode",
			DataDir: filepath.Join(home, ".defenseclaw"), AgentVersion: "2.1.230", Enabled: on}
	}
	manifestPath := filepath.Join(root, "targets.yaml")
	data, err := MarshalUnixTargetsManifest(Manifest{Version: 1, Targets: []ManifestTarget{
		row("svc", &enabled), row("carol", &enabled), row("dave", &enabled), row("erin", &disabled),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := enumeratorConfig("claudecode")
	cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"carol"}
	var asked []string
	_, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes},
		UIDMin: uid + 1, UIDMax: uid + 2, // svc is outside the automatic range
		DiscoverSurfaces: func(_ context.Context, account unixidentity.Account, _ []string) (UnixDiscovery, error) {
			asked = append(asked, account.Name)
			return UnixDiscovery{Versions: map[string]string{"claudecode": "2.1.230"}, PrivateInstalls: []PrivateAgentInstall{
				{Connector: "claudecode", Version: "2.0.77", Path: filepath.Join(account.Home, "old")},
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, ",") != "svc" {
		t.Fatalf("inspected %v, want only the authored, not excluded target svc", asked)
	}
	var got []string
	for _, agent := range report.Unprotected {
		got = append(got, agent.User+" "+agent.Code+" "+agent.Version)
	}
	sort.Strings(got)
	want := []string{"dave " + UnprotectedCodeInstallScanIncomplete + " ", "svc " + UnprotectedCodeHookContractUnverified + " 2.0.77"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("unprotected = %q, want %q", got, want)
	}
}

// Outside manifest enrollment, an enrolled account kept through a failed
// lookup was not inspected: it is incomplete, not silently clean.
func TestEnumerateUnixKeptAccountWithoutInspectionIsIncomplete(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	home := makeHome(t, homes, "ldapuser")
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	data, err := MarshalUnixTargetsManifest(Manifest{Version: 1, Targets: []ManifestTarget{
		{User: "ldapuser", UserHome: home, UID: intPointer(uid), GID: intPointer(gid), Connector: "claudecode",
			DataDir: filepath.Join(home, ".defenseclaw"), AgentVersion: "2.1.230", Enabled: &enabled},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{"ldapuser": true}}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("claudecode"), connector.NewDefaultRegistry(), UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || len(report.Unprotected) != 1 || report.Unprotected[0].Code != UnprotectedCodeInstallScanIncomplete ||
		!strings.Contains(report.Unprotected[0].Reason, "lookup failed") {
		t.Fatalf("targets %+v, unprotected %+v", manifest.Targets, report.Unprotected)
	}
}

// End to end through the enumerator with the real scan: a healthy host's
// supported installs report nothing, and an old machine copy beside them
// is reported for the enrolled account, never for an excluded one.
func TestEnumerateUnixHealthyHostIsCleanAndAnOldMachineCopyIsReported(t *testing.T) {
	withExtendedUnixDiscovery(t)
	homes := filepath.Join(trustedTestDir(t), "home")
	machine := machineTestDir(t)
	machineA, machineB := filepath.Join(machine, "usr-local"), filepath.Join(machine, "usr")
	for _, dir := range []string{homes, machineA, machineB} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	withPrivateInstallMachinePrefixes(t, machineA, machineB)
	uid, gid := os.Getuid(), os.Getgid()
	alice, bob := makeHome(t, homes, "alice"), makeHome(t, homes, "bob")
	npmCopy(t, claudePackage(filepath.Join(alice, ".npm-global"), true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
	npmCopy(t, claudePackage(machineA, true), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
		"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"},
		"bob":   {Name: "bob", UID: uid, GID: gid, Home: bob, Shell: "/bin/bash"},
	}, listed: []string{"alice", "bob"}}
	cfg := enumeratorConfig("claudecode")
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"bob"}
	run := func() []UnprotectedAgent {
		_, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), UnixEnumerateOptions{
			Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
			MachinePolicyConnectors: []string{"claudecode"},
			DiscoverSurfaces: func(ctx context.Context, account unixidentity.Account, names []string) (UnixDiscovery, error) {
				version, _ := DiscoverUnixAgentVersion(ctx, account.Home, "claudecode", false)
				return UnixDiscovery{Versions: map[string]string{"claudecode": version},
					PrivateInstalls: DiscoverUnixPrivateAgentInstalls(account.Home, names)}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return report.Unprotected
	}
	if got := run(); len(got) != 0 {
		t.Fatalf("healthy host reported %+v", got)
	}
	old := npmCopy(t, claudePackage(machineB, true), "@anthropic-ai/claude-code", "2.0.77", "cli.js")
	got := run()
	if len(got) != 1 || got[0].User != "alice" || got[0].Version != "2.0.77" || got[0].InstallPath != old ||
		got[0].Code != UnprotectedCodeHookContractUnverified {
		t.Fatalf("old machine copy = %+v", got)
	}
}
