// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0132: the standalone Windows payload's embedded scanner runtime is
// told which scanner to run, takes the judge from config-derived variables,
// and never sees a shell's SKILL_SCANNER_* or DEFENSECLAW_* settings.
func TestScannerRuntimeCommandLines(t *testing.T) {
	runtimeBinary := "C:/Program Files/Cisco/DefenseClaw/bin/defenseclaw-scanners.exe"
	skill := &SkillScanner{Config: config.SkillScannerConfig{Binary: runtimeBinary}}
	if got := skill.commandArgs("C:/s", "quiet"); got[0] != "skill-scanner" || got[1] != "scan" {
		t.Fatalf("skill args = %v", got)
	}
	plain := &SkillScanner{Config: config.SkillScannerConfig{Binary: "skill-scanner"}}
	if got := plain.commandArgs("C:/s", "quiet"); got[0] != "scan" {
		t.Fatalf("plain skill args = %v", got)
	}

	t.Setenv("DEFENSECLAW_SCANNER_LLM_MODEL", "from-shell")
	t.Setenv("SKILL_SCANNER_LLM_MODEL", "from-shell")
	// GAP-0274: the runtime gets the whole scanners.mcp_scanner block, so
	// the pinned extra YARA rules reach the scan.
	includeBundled := false
	rule := config.AssetFileRef{Path: `C:\ProgramData\Acme\mcp-marker.yar`, Digest: "sha256:" + strings.Repeat("ab", 32)}
	mcp := &MCPScanner{
		Config: config.MCPScannerConfig{
			Binary: runtimeBinary, Analyzers: []string{"yara", "llm"},
			YARA: config.MCPScannerYARAConfig{IncludeBundled: &includeBundled, ExtraRules: []config.AssetFileRef{rule}},
		},
		LLM: config.LLMConfig{Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", APIKey: "k", Region: "us-east-1"},
	}
	args, err := mcp.commandArgs("https://mcp.example.test/mcp")
	if err != nil || !reflect.DeepEqual(args, []string{"mcp-scan", "--input-stdin", "https://mcp.example.test/mcp"}) {
		t.Fatalf("mcp args = %v (%v)", args, err)
	}
	var settings struct {
		Analyzers []string `json:"analyzers"`
		Binary    *string  `json:"binary"`
		YARA      struct {
			IncludeBundled *bool `json:"include_bundled"`
			ExtraRules     []struct {
				Path   string `json:"path"`
				Digest string `json:"digest"`
			} `json:"extra_rules"`
		} `json:"yara"`
	}
	input, err := mcp.runtimeInput()
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Settings json.RawMessage `json:"settings"`
	}
	if err := json.Unmarshal(input, &payload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload.Settings, &settings); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if !reflect.DeepEqual(settings.Analyzers, []string{"yara", "llm"}) || settings.Binary != nil ||
		settings.YARA.IncludeBundled == nil || *settings.YARA.IncludeBundled ||
		len(settings.YARA.ExtraRules) != 1 || settings.YARA.ExtraRules[0].Path != rule.Path || settings.YARA.ExtraRules[0].Digest != rule.Digest {
		t.Fatalf("runtime settings = %s", payload.Settings)
	}
	// GAP-0296: the runtime also gets the rule pack the CLI overlays.
	mcp.RulePack = MCPRulePack{
		Dir:   `C:\ProgramData\DefenseClaw\policies\guardrail\strict`,
		Rules: []config.GuardrailRulesConfig{{Disable: []string{"SEC-X"}}},
	}
	args, err = mcp.commandArgs("https://mcp.example.test/mcp")
	if err != nil || len(args) != 3 {
		t.Fatalf("mcp args with rule pack = %v (%v)", args, err)
	}
	input, err = mcp.runtimeInput()
	if err != nil || !strings.Contains(string(input), `"rules":[{"disable":["SEC-X"]}]`) {
		t.Fatalf("mcp input lost rule pack: %v", err)
	}
	env := strings.Join(mcp.runtimeEnv(), "\n")
	for _, wantLine := range []string{
		"DEFENSECLAW_SCANNER_LLM_MODEL=bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
		"DEFENSECLAW_SCANNER_LLM_API_KEY=k",
		"AWS_REGION=us-east-1",
	} {
		if !strings.Contains(env, wantLine) {
			t.Fatalf("runtime env lacks %q", wantLine)
		}
	}
	if strings.Contains(env, "from-shell") {
		t.Fatal("a shell scanner variable reached the runtime")
	}
	// Python's platform.machine() needs PROCESSOR_ARCHITECTURE on Windows.
	t.Setenv("PROCESSOR_ARCHITECTURE", "AMD64")
	if !strings.Contains(strings.Join(skill.scanEnv(), "\n"), "PROCESSOR_ARCHITECTURE=AMD64") {
		t.Fatal("the scanner environment drops PROCESSOR_ARCHITECTURE")
	}

	plugin := &PluginScanner{BinaryPath: runtimeBinary, Connector: "codex", IncludeSelf: true}
	if _, args := plugin.pluginScanCommand("C:/p"); !reflect.DeepEqual(args, []string{"plugin-scan", "C:/p", "--connector", "codex", "--include-self"}) {
		t.Fatalf("plugin args = %v", args)
	}
}

// GAP-0710: the Windows runtime must receive the exact stdio definition,
// not only its name (which the wrapper would otherwise parse as a URL).
func TestMCPRuntimeStdioEntry(t *testing.T) {
	mcp := &MCPScanner{
		Config: config.MCPScannerConfig{Binary: "defenseclaw-scanners.exe"},
		ServerEntry: &config.MCPServerEntry{
			Name: "local", Command: "npx", Args: []string{"-y", "example-mcp"},
			Env: map[string]string{"MODE": "test"},
		},
	}
	args, err := mcp.commandArgs("local")
	if err != nil || !slices.Contains(args, "--input-stdin") {
		t.Fatalf("local runtime args = %v (%v)", args, err)
	}
	for _, arg := range args {
		if strings.Contains(arg, "example-mcp") || strings.Contains(arg, "MODE") {
			t.Fatalf("server definition leaked to command line: %v", args)
		}
	}
	input, err := mcp.runtimeInput()
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ServerEntry json.RawMessage `json:"server_entry"`
	}
	if err := json.Unmarshal(input, &payload); err != nil {
		t.Fatal(err)
	}
	body := payload.ServerEntry
	var entry struct {
		Name    string            `json:"name"`
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
		CWD     string            `json:"cwd"`
	}
	if err := json.Unmarshal(body, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Name != "local" || entry.Command != "npx" ||
		!reflect.DeepEqual(entry.Args, []string{"-y", "example-mcp"}) ||
		entry.Env["MODE"] != "test" || entry.CWD != "" {
		t.Fatalf("stdio entry lost launch fields: %+v", entry)
	}
}

// GAP-1317: the runtime starts a project's server in its cwd, else in the
// project, never in the gateway's folder; a cwd that leaves the project and
// the user's home through a link is not used.
func TestMCPRuntimeServerWorkDir(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, outside := filepath.Join(base, "home"), filepath.Join(base, "outside")
	project := filepath.Join(home, "project")
	sub := filepath.Join(project, "server")
	for _, dir := range []string{sub, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(project, "link")
	linked := os.Symlink(outside, link) == nil
	for _, tc := range []struct{ cwd, want string }{
		{"", project}, {sub, sub}, {"server", project}, {outside, project}, {link, project},
	} {
		if tc.cwd == link && !linked {
			continue
		}
		mcp := &MCPScanner{ServerEntry: &config.MCPServerEntry{Name: "local", Command: "uvx",
			Args: []string{"example-mcp"}, CWD: tc.cwd, Project: project, Home: home}}
		input, err := mcp.runtimeInput()
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			ServerEntry struct {
				CWD string `json:"cwd"`
			} `json:"server_entry"`
		}
		if err := json.Unmarshal(input, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.ServerEntry.CWD != tc.want {
			t.Fatalf("cwd %q: server starts in %q, want %q", tc.cwd, payload.ServerEntry.CWD, tc.want)
		}
	}
}

// GAP-1317: on managed Windows the gateway service account cannot stat the
// user profile. A folder the enumerator verified is used without that walk;
// an unverified one is refused, as is a verified one the gateway cannot open
// or that is outside the project and home, and a failed scan says why.
func TestMCPRuntimeVerifiedServerWorkDir(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "project")
	denied := filepath.Join(project, "denied")
	restoreLstat, restoreOpen := workDirLstat, workDirOpen
	t.Cleanup(func() { workDirLstat, workDirOpen = restoreLstat, restoreOpen })
	workDirLstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
	workDirOpen = func(path string) (*os.File, error) {
		if path == denied {
			return nil, os.ErrPermission
		}
		return os.Open(os.DevNull)
	}
	for _, tc := range []struct {
		name, workDir, refusedIn, want, note string
	}{
		{"verified", project, "", project, ""},
		{"verified after refused cwd", project, "C:\\link: link", project, ""},
		{"unverified", "", "", "", "permission denied"},
		{"refused by the enumerator", "", "C:\\other: in another user profile", "", "in another user profile"},
		{"gateway cannot read it", denied, "", "", "gateway service cannot read"},
		{"outside project and home", filepath.Join(t.TempDir(), "x"), "", "", "outside the project"},
	} {
		mcp := &MCPScanner{ServerEntry: &config.MCPServerEntry{Name: "local", Command: "npx", Args: []string{"-y", "."},
			Project: project, Home: home, WorkDir: tc.workDir, WorkDirRefused: tc.refusedIn}}
		if got := mcp.serverWorkDir(); got != tc.want {
			t.Errorf("%s: server starts in %q, want %q", tc.name, got, tc.want)
		}
		if note := mcp.workDirNote(); (tc.note == "") != (note == "") || !strings.Contains(note, tc.note) {
			t.Errorf("%s: failure note %q, want one containing %q", tc.name, note, tc.note)
		}
	}
}

// Large pinned rule sets are carried on stdin, outside the Windows command line.
func TestMCPRuntimeLargeSettingsStayOffCommandLine(t *testing.T) {
	rules := make([]config.AssetFileRef, 200)
	for i := range rules {
		rules[i] = config.AssetFileRef{Path: strings.Repeat("long-directory/", 20) + "rule.yar",
			Digest: "sha256:" + strings.Repeat("ab", 32)}
	}
	mcp := &MCPScanner{Config: config.MCPScannerConfig{Binary: "defenseclaw-scanners.exe",
		YARA: config.MCPScannerYARAConfig{ExtraRules: rules}}}
	args, err := mcp.commandArgs("server")
	if err != nil || len(strings.Join(args, " ")) > 100 {
		t.Fatalf("runtime arguments grew with settings: %v", err)
	}
	input, err := mcp.runtimeInput()
	if err != nil || len(input) < 32767 || !strings.Contains(string(input), "rule.yar") {
		t.Fatalf("large scanner settings did not reach stdin: %v", err)
	}
}

// GAP-0711: inherited endpoint overrides, including service-specific ones,
// cannot change the Bedrock judge destination in either scanner subprocess.
func TestScannerAWSConfiguredEndpointsIgnored(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "https://inherited.example.test")
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "https://inherited.example.test")
	t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")
	t.Setenv("AWS_PROFILE", "credential-profile")
	skill := &SkillScanner{Config: config.SkillScannerConfig{UseLLM: true},
		LLM: config.LLMConfig{Provider: "bedrock", Model: "bedrock/test"}}
	mcp := &MCPScanner{LLM: config.LLMConfig{Provider: "bedrock", Model: "bedrock/test"}}
	for name, env := range map[string][]string{"skill": skill.scanEnv(), "mcp": mcp.runtimeEnv()} {
		vars := map[string]string{}
		for _, line := range env {
			key, value, _ := strings.Cut(line, "=")
			vars[strings.ToUpper(key)] = value
		}
		if vars["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] != "true" ||
			vars["AWS_ENDPOINT_URL"] != "" || vars["AWS_ENDPOINT_URL_BEDROCK_RUNTIME"] != "" ||
			vars["AWS_PROFILE"] != "credential-profile" {
			t.Fatalf("%s AWS endpoint settings are not pinned", name)
		}
	}
}
