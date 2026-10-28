//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestManagedWindowsReportsOldClaudeBesideSupportedInstall(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"), "2.1.230")
	old := filepath.Join(home, "private-old", "node_modules", "@anthropic-ai", "claude-code")
	writeWindowsAgentPackageJSON(t, old, "2.0.77")
	if err := os.WriteFile(filepath.Join(old, "cli.js"), []byte("// fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(home, ".local", "share", "claude", "versions")
	if err := os.MkdirAll(native, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "2.0.0"), []byte("native fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	var uncovered []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("claudecode"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { uncovered = append(uncovered, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != "2.1.230" {
		t.Fatalf("supported install lost its row: %+v", manifest.Targets)
	}
	if len(uncovered) != 2 || uncovered[0].Version != "2.0.77" ||
		uncovered[0].Code != UnprotectedCodeHookContractUnverified || !strings.Contains(uncovered[0].Message(), "private-old") ||
		uncovered[1].Version != "2.0.0" || !strings.Contains(uncovered[1].Message(), "versions") {
		t.Fatalf("old runnable copy was not reported: %+v", uncovered)
	}
}

func TestManagedWindowsReportsClaudeLocalBesideSupportedInstall(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"), "2.1.230")
	old := filepath.Join(home, ".claude", "local", "node_modules", "@anthropic-ai", "claude-code")
	writeWindowsAgentPackageJSON(t, old, "2.0.77")
	if err := os.WriteFile(filepath.Join(old, "cli.js"), []byte("// fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "local", "claude.cmd"), []byte("@echo off\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	var uncovered []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("claudecode"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { uncovered = append(uncovered, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != "2.1.230" ||
		len(uncovered) != 1 || uncovered[0].Version != "2.0.77" || uncovered[0].InstallPath != old {
		t.Fatalf("vendor local old copy hidden: targets=%+v uncovered=%+v", manifest.Targets, uncovered)
	}
}

func TestManagedWindowsReportsOldVoltaImagesBesideSupportedInstall(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"), "2.1.230")
	packages := map[string]string{"claudecode": "@anthropic-ai/claude-code", "codex": "@openai/codex", "copilot": "@github/copilot"}
	old := map[string]string{}
	for connector, pkg := range packages {
		old[connector] = filepath.Join(home, "AppData", "Local", "Volta", "tools", "image", "packages", filepath.FromSlash(pkg), "node_modules", filepath.FromSlash(pkg))
		writeWindowsAgentPackageJSON(t, old[connector], "0.0.1")
	}
	for connector, entry := range map[string]string{"claudecode": "cli.js", "codex": `bin\codex.js`, "copilot": "npm-loader.js"} {
		windowsClaudeCopy(t, old[connector], "0.0.1", entry)
	}
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	var uncovered []UnprotectedAgent
	cfg := standaloneEnumeratorConfig("claudecode")
	enabled := true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Enabled: &enabled}, "codex": {Enabled: &enabled}, "copilot": {Enabled: &enabled},
	}
	manifest, err := EnumerateWindows(context.Background(), cfg, EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { uncovered = append(uncovered, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	supported := false
	for _, target := range manifest.Targets {
		supported = supported || target.Connector == "claudecode" && target.AgentVersion == "2.1.230"
	}
	if !supported {
		t.Fatalf("supported npm copy lost its enrollment: %+v", manifest.Targets)
	}
	for connector, path := range old {
		found := false
		for _, agent := range uncovered {
			found = found || agent.Connector == connector && agent.InstallPath == path && agent.Code == UnprotectedCodeHookContractUnverified
		}
		if !found {
			t.Fatalf("%s Volta image hidden: %+v", connector, uncovered)
		}
	}
}

func TestDiscoverWindowsClaudeLocalWrapperWithoutMetadataIsUnprotected(t *testing.T) {
	home := t.TempDir()
	wrapper := filepath.Join(home, ".claude", "local", "claude.cmd")
	if err := os.MkdirAll(filepath.Dir(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapper, []byte("@echo off\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := DiscoverWindowsPrivateAgentInstalls(context.Background(), home, []string{"claudecode"})
	found := false
	for _, item := range findings {
		found = found || item.Path == wrapper && item.Version == "" && !item.Incomplete
	}
	if !found {
		t.Fatalf("unversioned vendor wrapper = %+v", findings)
	}
}

func TestDiscoverWindowsPrivateClaudeWithoutVersionIsUnprotected(t *testing.T) {
	home := t.TempDir()
	entry := filepath.Join(home, "private", "node_modules", "@anthropic-ai", "claude-code", "cli.js")
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("// fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(home, ".local", "share", "claude", "versions", "unknown")
	if err := os.MkdirAll(filepath.Dir(native), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(native, []byte("native fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := DiscoverWindowsPrivateAgentInstalls(context.Background(), home, []string{"claudecode"})
	if len(findings) != 2 || findings[0].Version != "" || findings[1].Version != "" ||
		findings[0].Path == findings[1].Path {
		t.Fatalf("unversioned runnable copies = %+v", findings)
	}
}

func TestDiscoverWindowsPrivateCodexAndCopilotBelowContract(t *testing.T) {
	home := t.TempDir()
	for pkg, entry := range map[string]string{"@openai/codex": `bin\codex.js`, "@github/copilot": "npm-loader.js"} {
		windowsClaudeCopy(t, filepath.Join(home, "private", "node_modules", filepath.FromSlash(pkg)), "0.0.1", entry)
	}
	findings := DiscoverWindowsPrivateAgentInstalls(context.Background(), home, []string{"codex", "copilot"})
	if len(findings) != 2 || findings[0].Connector != "codex" || findings[1].Connector != "copilot" {
		t.Fatalf("private npm agent versions = %+v", findings)
	}
}
