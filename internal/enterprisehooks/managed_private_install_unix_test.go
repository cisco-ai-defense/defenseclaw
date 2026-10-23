//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func TestManagedUnixReportsOldClaudeInPrivatePrefix(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			root := trustedTestDir(t)
			homes := filepath.Join(root, "homes")
			if err := os.MkdirAll(homes, 0o755); err != nil {
				t.Fatal(err)
			}
			home := makeHome(t, homes, "alice")
			uid, gid := os.Getuid(), os.Getgid()
			resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
				"alice": {Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"},
			}, listed: []string{"alice"}}
			cfg := enumeratorConfig("claudecode")
			var asked []string
			_, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), UnixEnumerateOptions{
				Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
				MachinePolicyConnectors: []string{"claudecode"},
				DiscoverSurfaces: func(_ context.Context, _ unixidentity.Account, names []string) (UnixDiscovery, error) {
					asked = append(asked, names...)
					return UnixDiscovery{Versions: map[string]string{"claudecode": "2.0.77"}}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(asked, ","), "claudecode") || len(report.Unprotected) != 1 ||
				report.Unprotected[0].Code != UnprotectedCodeHookContractUnverified || report.Unprotected[0].Version != "2.0.77" {
				t.Fatalf("%s: discovery asked %v; unprotected %+v", platform, asked, report.Unprotected)
			}
		})
	}
}

func TestDiscoverUnixPrivateClaudeCopiesKeepsEveryOldVersion(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	write := func(prefix, version string) {
		t.Helper()
		dir := filepath.Join(home, prefix, "node_modules", "@anthropic-ai", "claude-code")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"`+version+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cli.js"), []byte("// fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("supported", "2.1.230")
	write("sa104r8-old", "2.0.77")
	write("another-old", "1.0.128")
	native := filepath.Join(home, ".local", "share", "claude", "versions")
	if err := os.MkdirAll(native, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "2.0.0"), []byte("native fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	findings := DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode"})
	if len(findings) != 3 {
		t.Fatalf("private copies = %+v, want both old npm installs and native release", findings)
	}
	versions := map[string]bool{}
	for _, found := range findings {
		versions[found.Version] = true
		if found.Path == "" || found.Incomplete {
			t.Fatalf("incomplete private finding: %+v", found)
		}
	}
	if !versions["2.0.77"] || !versions["1.0.128"] || !versions["2.0.0"] {
		t.Fatalf("private copies = %+v", findings)
	}
}

func TestDiscoverUnixClaudeLocalAndVoltaCopiesBesideSupportedInstall(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	write := func(root, version string) string {
		t.Helper()
		dir := filepath.Join(home, root, "node_modules", "@anthropic-ai", "claude-code")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"`+version+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cli.js"), []byte("// fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	write(".npm-global", "2.1.230")
	local := write(filepath.Join(".claude", "local"), "2.0.77")
	volta := write(filepath.Join(".volta", "tools", "image", "packages", "@anthropic-ai", "claude-code"), "2.0.76")
	if err := os.WriteFile(filepath.Join(home, ".claude", "local", "claude"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode"})
	if len(got) != 2 || got[0].Path != local || got[0].Version != "2.0.77" ||
		got[1].Path != volta || got[1].Version != "2.0.76" {
		t.Fatalf("vendor local and Volta old copies = %+v", got)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "claudecode", false); version != "2.1.230" {
		t.Fatalf("main probe lost the supported global copy: %q", version)
	}
}

func TestDiscoverUnixClaudeLocalIsMainProbeCandidate(t *testing.T) {
	previousExtended := unixUserDiscoveryExtended
	unixUserDiscoveryExtended = func() bool { return true } // managed per-user worker
	t.Cleanup(func() { unixUserDiscoveryExtended = previousExtended })
	home := makeHome(t, trustedTestDir(t), "alice")
	dir := filepath.Join(home, ".claude", "local", "node_modules", "@anthropic-ai", "claude-code")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"2.0.77"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "claudecode", false); version != "2.0.77" {
		t.Fatalf("vendor local version = %q", version)
	}
}

func TestDiscoverUnixClaudeLocalDoesNotReplaceSupportedMachineCopy(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	for root, version := range map[string]string{"machine": "2.1.230", filepath.Join(".claude", "local"): "2.0.77"} {
		dir := filepath.Join(home, root, "lib", "node_modules", "@anthropic-ai", "claude-code")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"`+version+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	original := machinePrefixes
	machinePrefixes = func() []string { return []string{filepath.Join(home, "machine")} }
	t.Cleanup(func() { machinePrefixes = original })
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "claudecode", false); version != "2.1.230" {
		t.Fatalf("vendor local copy replaced supported machine version: %q", version)
	}
}

func TestDiscoverUnixClaudeLocalWrapperWithoutMetadataIsUnprotected(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	wrapper := filepath.Join(home, ".claude", "local", "claude")
	if err := os.MkdirAll(filepath.Dir(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	findings := DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode"})
	if len(findings) != 1 || findings[0].Path != wrapper || findings[0].Version != "" || findings[0].Incomplete {
		t.Fatalf("unversioned vendor wrapper = %+v", findings)
	}
}

func TestDiscoverUnixPrivateClaudeWithoutVersionIsUnprotected(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	entry := filepath.Join(home, "private", "node_modules", "@anthropic-ai", "claude-code", "cli.js")
	if err := os.MkdirAll(filepath.Dir(entry), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("// fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(home, ".local", "share", "claude", "versions", "unknown")
	if err := os.MkdirAll(filepath.Dir(native), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(native, []byte("native fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	findings := DiscoverUnixPrivateAgentInstalls(home, []string{"claudecode"})
	if len(findings) != 2 || findings[0].Version != "" || findings[1].Version != "" ||
		findings[0].Path == findings[1].Path {
		t.Fatalf("unversioned runnable copies = %+v", findings)
	}
}

func TestDiscoverUnixPrivateCodexAndCopilotBelowContract(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	for pkg, entry := range map[string]string{"@openai/codex": "bin/codex.js", "@github/copilot": "npm-loader.js"} {
		npmCopy(t, filepath.Join(home, "private", "node_modules", filepath.FromSlash(pkg)), pkg, "0.0.1", entry)
	}
	findings := DiscoverUnixPrivateAgentInstalls(home, []string{"codex", "copilot"})
	if len(findings) != 2 || findings[0].Connector != "codex" || findings[1].Connector != "copilot" {
		t.Fatalf("private npm agent versions = %+v", findings)
	}
}

func TestDiscoverUnixVoltaCodexAndCopilotCopies(t *testing.T) {
	home := makeHome(t, trustedTestDir(t), "alice")
	for pkg, entry := range map[string]string{"@openai/codex": "bin/codex.js", "@github/copilot": "npm-loader.js"} {
		npmCopy(t, filepath.Join(home, ".volta", "tools", "image", "packages", filepath.FromSlash(pkg),
			"node_modules", filepath.FromSlash(pkg)), pkg, "0.0.1", entry)
	}
	findings := DiscoverUnixPrivateAgentInstalls(home, []string{"codex", "copilot"})
	if len(findings) != 2 || findings[0].Connector != "codex" || findings[1].Connector != "copilot" {
		t.Fatalf("old Volta package copies = %+v", findings)
	}
}
