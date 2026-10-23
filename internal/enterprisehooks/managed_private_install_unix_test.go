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
	for _, pkg := range []string{"@openai/codex", "@github/copilot"} {
		path := filepath.Join(home, "private", "node_modules", filepath.FromSlash(pkg), "package.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"name":"`+pkg+`","version":"0.0.1"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings := DiscoverUnixPrivateAgentInstalls(home, []string{"codex", "copilot"})
	if len(findings) != 2 || findings[0].Connector != "codex" || findings[1].Connector != "copilot" {
		t.Fatalf("private npm agent versions = %+v", findings)
	}
}
