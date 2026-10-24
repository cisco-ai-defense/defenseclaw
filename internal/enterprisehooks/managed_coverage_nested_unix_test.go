//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func withPrivateInstallWalkBound(t *testing.T, bound int) {
	t.Helper()
	previous := privateInstallWalkMaxEntries
	privateInstallWalkMaxEntries = bound
	t.Cleanup(func() { privateInstallWalkMaxEntries = previous })
}

// A runnable copy is found wherever below the home the account put it, at
// any depth (GAP-0988: a 2.0.77 copy moved to ~/r21-holder/deep/r21-copy
// vanished from the scan while status said complete). A scan that could
// not finish says so; it never reports the account clean.
func TestDiscoverUnixPrivateInstallsFindCopiesAtAnyDepth(t *testing.T) {
	old := func(t *testing.T, dir string) { npmCopy(t, dir, "@anthropic-ai/claude-code", "2.0.77", "cli.js") }
	cases := []struct {
		name  string
		bound int
		build func(t *testing.T, home string)
		want  []string
	}{
		{
			name: "the R21 move: npm --prefix copy two folders down",
			build: func(t *testing.T, home string) {
				old(t, claudePackage(filepath.Join(home, "r21-holder", "deep", "r21-copy"), false))
			},
			want: []string{"claudecode 2.0.77 /r21-holder/deep/r21-copy/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "a global-style prefix twelve folders down",
			build: func(t *testing.T, home string) {
				prefix := filepath.Join(append([]string{home}, strings.Split("a/b/c/d/e/f/g/h/i/j/k/l", "/")...)...)
				npmCopy(t, filepath.Join(prefix, "lib", "node_modules", "@openai", "codex"), "@openai/codex", "0.0.1", "bin/codex.js")
			},
			want: []string{"codex 0.0.1 /a/b/c/d/e/f/g/h/i/j/k/l/lib/node_modules/@openai/codex"},
		},
		{
			name: "a nested dependency of a project's package",
			build: func(t *testing.T, home string) {
				npmCopy(t, filepath.Join(home, "proj", "node_modules", "wrapper"), "wrapper", "1.0.0", "index.js")
				old(t, claudePackage(filepath.Join(home, "proj", "node_modules", "wrapper"), false))
			},
			want: []string{"claudecode 2.0.77 /proj/node_modules/wrapper/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "a pnpm store entry and its link are one copy",
			build: func(t *testing.T, home string) {
				store := filepath.Join(home, "src", "proj", "node_modules", ".pnpm", "@anthropic-ai+claude-code@2.0.77")
				old(t, claudePackage(store, false))
				scope := filepath.Join(home, "src", "proj", "node_modules", "@anthropic-ai")
				if err := os.MkdirAll(scope, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(claudePackage(store, false), filepath.Join(scope, "claude-code")); err != nil {
					t.Fatal(err)
				}
			},
			// One copy, named by whichever spelling the walk meets first.
			want: []string{"claudecode 2.0.77 /src/proj/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name: "a supported nested copy and link loops report nothing",
			build: func(t *testing.T, home string) {
				npmCopy(t, claudePackage(filepath.Join(home, "x", "y", "tools"), false), "@anthropic-ai/claude-code", "2.1.230", "bin/claude.exe")
				if err := os.Symlink(home, filepath.Join(home, "x", "loop")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(home, "x"), filepath.Join(home, "x", "y", "up")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:  "package contents are not listed, so a crowded package does not use the bound",
			bound: 64,
			build: func(t *testing.T, home string) {
				pkg := filepath.Join(home, "src", "proj", "node_modules", "big")
				for i := 0; i < 200; i++ {
					if err := os.MkdirAll(filepath.Join(pkg, fmt.Sprintf("d%03d", i)), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				old(t, claudePackage(filepath.Join(home, "src", "proj"), false))
			},
			want: []string{"claudecode 2.0.77 /src/proj/node_modules/@anthropic-ai/claude-code"},
		},
		{
			name:  "a home over the walk bound is incomplete, and what was found is kept",
			bound: 32,
			build: func(t *testing.T, home string) {
				for i := 0; i < 40; i++ {
					if err := os.MkdirAll(filepath.Join(home, "many", fmt.Sprintf("d%02d", i)), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			},
			want: []string{"claudecode incomplete " + PrivateInstallSkippedHome, "codex incomplete " + PrivateInstallSkippedHome},
		},
		{
			name: "a folder the account owns but made unlistable is incomplete",
			build: func(t *testing.T, home string) {
				if os.Geteuid() == 0 {
					t.Skip("root lists every folder")
				}
				hidden := filepath.Join(home, "hide")
				old(t, claudePackage(filepath.Join(hidden, "secret"), false))
				if err := os.Chmod(hidden, 0o300); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })
			},
			want: []string{"claudecode incomplete " + PrivateInstallSkippedHome, "codex incomplete " + PrivateInstallSkippedHome},
		},
		{
			name: "a folder the account owns but made unsearchable is incomplete",
			build: func(t *testing.T, home string) {
				if os.Geteuid() == 0 {
					t.Skip("root can search every folder")
				}
				hidden := filepath.Join(home, "hide")
				old(t, claudePackage(filepath.Join(hidden, "secret"), false))
				if err := os.Chmod(hidden, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })
			},
			want: []string{"claudecode incomplete " + PrivateInstallSkippedHome, "codex incomplete " + PrivateInstallSkippedHome},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bound > 0 {
				withPrivateInstallWalkBound(t, tc.bound)
			}
			home := makeHome(t, trustedTestDir(t), "alice")
			tc.build(t, home)
			var got []string
			for _, line := range describeInstalls(t, DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode", "codex"}), home) {
				got = append(got, strings.ReplaceAll(line, "/.pnpm/@anthropic-ai+claude-code@2.0.77/node_modules/", "/"))
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("copies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// A Homebrew cask release is judged when its CLI sits below the release
// folder (GAP-0989: Caskroom/codex/<version>/bin/codex was skipped), and a
// release too crowded to read is judged by its version, not skipped.
func TestDiscoverUnixPrivateInstallsJudgeNestedCaskExecutables(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, caskroom string)
		want  []string
	}{
		{name: "bin/codex", build: func(t *testing.T, caskroom string) {
			npmCopy(t, filepath.Join(caskroom, "codex", "0.0.1", "bin"), "unused", "0", "codex")
		}, want: []string{"codex 0.0.1 MACHINE/Caskroom/codex/0.0.1"}},
		{name: "two folders down", build: func(t *testing.T, caskroom string) {
			npmCopy(t, filepath.Join(caskroom, "claude-code", "2.0.77", "claude-code-darwin", "bin"), "unused", "0", "claude")
		}, want: []string{"claudecode 2.0.77 MACHINE/Caskroom/claude-code/2.0.77"}},
		{name: "a crowded release", build: func(t *testing.T, caskroom string) {
			release := filepath.Join(caskroom, "codex", "0.0.2")
			for i := 0; i <= privateAgentInstallMaxVersionDirs; i++ {
				if err := os.MkdirAll(filepath.Join(release, fmt.Sprintf("doc%02d", i)), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}, want: []string{"codex 0.0.2 MACHINE/Caskroom/codex/0.0.2"}},
		{name: "a supported nested release and a release without a CLI report nothing", build: func(t *testing.T, caskroom string) {
			npmCopy(t, filepath.Join(caskroom, "claude-code", "2.1.230", "bin"), "unused", "0", "claude")
			if err := os.MkdirAll(filepath.Join(caskroom, "codex", "0.0.3", "share", "doc"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			machine := filepath.Join(machineTestDir(t), "machine")
			withPrivateInstallMachinePrefixes(t, machine)
			tc.build(t, filepath.Join(machine, "Caskroom"))
			home := makeHome(t, trustedTestDir(t), "alice")
			var got []string
			for _, line := range describeInstalls(t, DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode", "codex"}), home) {
				got = append(got, strings.ReplaceAll(line, machine, "MACHINE"))
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("copies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// A row kept for an account the cycle could not inspect leaves coverage
// incomplete (GAP-0990): a "no such user" the directory may have given
// while it was down, in either enrollment mode, and an include-group miss
// that is not yet confirmed. An account confirmed gone runs nothing.
func TestEnumerateUnixKeptRowsOfUninspectedAccountsAreIncomplete(t *testing.T) {
	const alice, carol, dana = 1234401103, 1500, 2001
	for _, tc := range []struct {
		name     string
		manifest bool
		answered bool // another directory account resolved this cycle
		filtered bool // dana resolves but left the include group
		want     []string
	}{
		{name: "directory outage, automatic enrollment", want: []string{"alice"}},
		{name: "directory outage, manifest enrollment", manifest: true, want: []string{"alice"}},
		{name: "directory answering: the miss is definitive", answered: true},
		// dana resolving shows the directory answering, so alice's miss is
		// definitive here.
		{name: "left the include group, not yet confirmed", filtered: true, want: []string{"dana"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedTestDir(t)
			homes := filepath.Join(root, "home")
			manifestPath := filepath.Join(root, "targets.yaml")
			targets := []ManifestTarget{
				{User: "alice", UserHome: filepath.Join(homes, "alice"), UID: intPointer(alice), GID: intPointer(alice), Connector: "opencode", AgentVersion: "1.18.33", HomeInode: 42},
				{User: "carol", UserHome: filepath.Join(homes, "carol"), UID: intPointer(carol), GID: intPointer(carol), Connector: "opencode", AgentVersion: "1.18.33", HomeInode: 42},
			}
			resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
				"root": {Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
			}, listed: []string{"root"}, groups: map[string][]int{"dana": {}}, groupNames: map[int]string{5001: "ai-devs"}}
			if tc.answered {
				resolver.accounts["bob"] = unixidentity.Account{Name: "bob", UID: 1234401200, GID: 1234401200, Home: filepath.Join(homes, "bob"), Shell: "/bin/bash"}
				resolver.listed = append(resolver.listed, "bob")
			}
			cfg := enumeratorConfig("opencode")
			if tc.filtered {
				targets = append(targets, ManifestTarget{User: "dana", UserHome: filepath.Join(homes, "dana"), UID: intPointer(dana), GID: intPointer(dana), Connector: "opencode", AgentVersion: "1.18.33", HomeInode: 42})
				resolver.accounts["dana"] = unixidentity.Account{Name: "dana", UID: dana, GID: dana, Home: filepath.Join(homes, "dana"), Shell: "/bin/bash"}
				resolver.listed = append(resolver.listed, "dana")
				cfg.Enterprise.Enrollment.IncludeGroups = []string{"ai-devs"}
			}
			if tc.manifest {
				cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
			}
			writeTestManifest(t, manifestPath, targets...)
			state := &UnixEnumeratorState{Version: 1, Misses: map[string]int{}, Sources: map[string]string{"alice": unixSourceDirectory, "carol": unixSourceFiles, "dana": unixSourceDirectory}}
			manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), UnixEnumerateOptions{
				ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: 1000, UIDMax: 60000,
				CheckHome: availableHome, State: state,
				LocalAccounts:       func() (map[string]int, error) { return map[string]int{"root": 0}, nil },
				DirectoryConfigured: func() bool { return true },
			})
			if err != nil {
				t.Fatal(err)
			}
			users := manifestUsers(manifest)
			if !users["carol"] || !users["alice"] || (tc.filtered && !users["dana"]) {
				t.Fatalf("kept rows %v", users)
			}
			var got []string
			for _, agent := range report.Unprotected {
				if agent.Code != UnprotectedCodeInstallScanIncomplete || agent.Connector != "opencode" {
					t.Fatalf("unexpected entry %+v", agent)
				}
				got = append(got, agent.User)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("incomplete accounts %v, want %v (%+v)", got, tc.want, report.Unprotected)
			}
		})
	}
}

// An editor extension or desktop app of a machine-policy agent runs its own
// engine; one below the hook contract can ignore the managed hooks as an
// old CLI does, so it is reported (GAP-1076: an anthropic.claude-code-2.0.77
// extension left status and verify complete).
func TestEnumerateUnixReportsOldSurfacesOfMachinePolicyAgents(t *testing.T) {
	extension := func(version string) connector.AgentSurface {
		return connector.AgentSurface{Surface: connector.HostSurfaceExtension, Host: "vscode", EngineVersion: version, HostVersion: version}
	}
	desktop := func(version string) connector.AgentSurface {
		return connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", EngineVersion: version}
	}
	for _, tc := range []struct {
		name     string
		cli      string
		surfaces []connector.AgentSurface
		fixture  string // a real extension folder, discovered for real
		want     []string
	}{
		{name: "the R29 metadata-only extension, discovered for real", fixture: "2.0.77", want: []string{"extension 2.0.77"}},
		{name: "old extension beside a supported CLI", cli: "2.1.230", surfaces: []connector.AgentSurface{extension("2.0.77")}, want: []string{"extension 2.0.77"}},
		{name: "old desktop engine", surfaces: []connector.AgentSurface{desktop("2.0.77")}, want: []string{"desktop 2.0.77"}},
		{name: "supported extension and desktop", cli: "2.1.230", surfaces: []connector.AgentSurface{extension("2.1.230"), desktop("2.1.230")}},
		{name: "a supported extension, discovered for real", fixture: "2.1.230"},
		{name: "an engine without a version is left to the surface checks", surfaces: []connector.AgentSurface{{Surface: connector.HostSurfaceExtension, Host: "vscode"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			homes := filepath.Join(trustedTestDir(t), "home")
			if err := os.MkdirAll(homes, 0o755); err != nil {
				t.Fatal(err)
			}
			uid, gid := os.Getuid(), os.Getgid()
			home := makeHome(t, homes, "alice")
			if tc.fixture != "" {
				dir := filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-"+tc.fixture)
				writeNPMManifest(t, dir, `{"name":"claude-code","version":"`+tc.fixture+`"}`)
			}
			resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
				"alice": {Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"},
			}, listed: []string{"alice"}}
			_, report, err := EnumerateUnix(context.Background(), enumeratorConfig("claudecode"), connector.NewDefaultRegistry(), UnixEnumerateOptions{
				Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
				MachinePolicyConnectors: []string{"claudecode"},
				DiscoverSurfaces: func(ctx context.Context, account unixidentity.Account, names []string) (UnixDiscovery, error) {
					surfaces := tc.surfaces
					if tc.fixture != "" {
						surfaces, _ = DiscoverUnixAgentSurfaces(ctx, account.Home, "claudecode", false)
					}
					return UnixDiscovery{Versions: map[string]string{"claudecode": tc.cli}, Surfaces: map[string][]connector.AgentSurface{"claudecode": surfaces}}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, agent := range report.Unprotected {
				if agent.User != "alice" || agent.Connector != "claudecode" || agent.Code != UnprotectedCodeHookContractUnverified {
					t.Fatalf("unexpected entry %+v", agent)
				}
				got = append(got, agent.Surface+" "+agent.Version)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("reported %v, want %v (%+v)", got, tc.want, report.Unprotected)
			}
		})
	}
}

// Extension discovery that could not read a whole extensions folder says
// so (GAP-1077: 16,385 entries hid an old extension and coverage stayed
// complete); a folder at the bound, an absent one and an unreachable one
// do not.
func TestDiscoverUnixAgentSurfacesReportsAnUnlistedExtensionsFolder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		entries  int
		absent   bool
		complete bool
	}{
		{name: "one entry over the bound", entries: unixExtensionMaxEntries + 1},
		{name: "at the bound", entries: unixExtensionMaxEntries, complete: true},
		{name: "no extensions folder", absent: true, complete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := makeHome(t, trustedTestDir(t), "alice")
			root := filepath.Join(home, ".vscode", "extensions")
			if !tc.absent {
				writeNPMManifest(t, filepath.Join(root, "anthropic.claude-code-2.0.77"), `{"name":"claude-code","version":"2.0.77"}`)
				for i := 1; i < tc.entries; i++ {
					if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("pad.ext-%05d", i)), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, complete := DiscoverUnixAgentSurfaces(context.Background(), home, "claudecode", false); complete != tc.complete {
				t.Fatalf("complete = %v, want %v", complete, tc.complete)
			}
		})
	}
	if KnownPrivateInstallSkipped(PrivateInstallSkippedExtensions) == "" {
		t.Fatal("the root parent must keep the extensions-folder code")
	}
	agent, ok := privateInstallUnprotected(PrivateAgentInstall{Connector: "claudecode", Incomplete: true, Skipped: PrivateInstallSkippedExtensions})
	if !ok || agent.Code != UnprotectedCodeInstallScanIncomplete || !strings.Contains(agent.Reason, "extensions folder") {
		t.Fatalf("incomplete extension scan = %+v", agent)
	}
}
