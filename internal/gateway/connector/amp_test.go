// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestAMPSetupWritesManagedSystemPlugin(t *testing.T) {
	root := t.TempDir()
	pluginPath := filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	conn := NewAMPConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "defenseclaw"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "amp-scoped-token",
		HookFailMode: "closed",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	info, err := os.Stat(pluginPath)
	if err != nil {
		t.Fatalf("plugin stat: %v", err)
	}
	if runtime.GOOS == "windows" {
		file, err := os.Open(pluginPath)
		if err != nil {
			t.Fatalf("open protected Amp plugin: %v", err)
		}
		privateErr := validateAtomicTransformBoundFilePrivatePlatform(file)
		closeErr := file.Close()
		if privateErr != nil {
			t.Fatalf("Amp Setup left plugin without a protected private DACL: %v", privateErr)
		}
		if closeErr != nil {
			t.Fatalf("close protected Amp plugin: %v", closeErr)
		}
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("plugin mode=%#o want 0600", got)
	}
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"127.0.0.1:18970",
		"amp-scoped-token",
		`const DC_FAIL_MODE: string = "closed"`,
		"/api/v1/amp/hook",
		`amp.on("session.start"`,
		`amp.on("agent.start"`,
		`amp.on("tool.call"`,
		`amp.on("tool.result"`,
		`amp.on("agent.end"`,
		`action: "reject-and-continue"`,
		`withheldToolResult`,
		`Share result`,
		"isPluginUINotAvailableError",
		"amp.activeThread.current",
		"source_sequence",
		"crypto.randomUUID()",
		"sourceSequence++",
		"ctx.thread.agent()",
		`definition.kind === "agent-definition"`,
		"agent_metadata_provenance",
		"agent_display_name",
		"agent_mode",
		"model: definition.model",
		`message.role !== "assistant"`,
		`block.type === "text"`,
		"tool_response: response",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered plugin missing %q", want)
		}
	}
	if strings.Contains(text, "{{.") {
		t.Fatal("rendered plugin retains template placeholders")
	}
	agentEnd := text[strings.Index(text, `amp.on("agent.end"`):]
	if strings.Contains(agentEnd, "messages: event.messages") || strings.Contains(agentEnd, "message: event.message") {
		t.Fatal("agent.end forwards the transcript or re-scans the user prompt")
	}
	if _, err := os.Stat(filepath.Join(opts.DataDir, "hooks", "amp-plugin.ts")); !os.IsNotExist(err) {
		t.Fatalf("Amp setup wrote a synthetic data-dir hook: err=%v", err)
	}
	if got := conn.HookRuntimeArtifacts(opts); len(got) != 1 || got[0] != pluginPath {
		t.Fatalf("HookRuntimeArtifacts=%v want [%s]", got, pluginPath)
	}
	if got := conn.AgentPaths(opts).HookScripts; len(got) != 1 || got[0] != pluginPath {
		t.Fatalf("AgentPaths.HookScripts=%v want [%s]", got, pluginPath)
	}
	if got := ManagedPluginArtifacts(conn, opts); len(got) != 1 || got[0] != pluginPath {
		t.Fatalf("ManagedPluginArtifacts=%v want [%s]", got, pluginPath)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after Setup = %v, %v; want true, nil", present, err)
	}
	if err := conn.VerifyClean(opts); err == nil {
		t.Fatal("VerifyClean accepted the installed managed Amp plugin")
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("plugin remains after teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func TestAMPTeardownRestoresPreExistingDefenseClawPluginAsClean(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	pluginPath := filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	pristine := []byte(
		"// Operator-owned DefenseClaw integration.\n" +
			"const endpoint = '/api/v1/amp/hook'\n" +
			"export default function operatorPlugin() {}\n",
	)
	if err := os.WriteFile(pluginPath, pristine, 0o600); err != nil {
		t.Fatal(err)
	}

	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })
	conn := NewAMPConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "amp-scoped-token",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	restored, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read restored plugin: %v", err)
	}
	if string(restored) != string(pristine) {
		t.Fatalf("restored plugin bytes differ\n got: %q\nwant: %q", restored, pristine)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean rejected restored pristine plugin: %v", err)
	}
}

func TestAMPOwnedHookContractRejectsIncompletePlugin(t *testing.T) {
	root := t.TempDir()
	pluginPath := filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	conn := NewAMPConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "amp-scoped-token",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), `amp.on("agent.end"`, `amp.on("agent.missing"`))
	if err := os.WriteFile(pluginPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("OwnedHooksPresent after tamper = %v, %v; want false, nil", present, err)
	}
}

func TestAMPRepeatSessionStartsUseUniqueOccurrenceIDs(t *testing.T) {
	data, err := hookFS.ReadFile("hooks/amp-plugin.ts")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "const processNonce = crypto.randomUUID()") ||
		!strings.Contains(text, "sourceSequence++") ||
		!strings.Contains(text, "const sequence = sourceSequence") ||
		!strings.Contains(text, "source_sequence: String(sequence)") {
		t.Fatal("Amp plugin does not combine a process nonce with monotonic source sequence")
	}
	if !strings.Contains(text, "${processNonce}:${sequence}") {
		t.Fatal("Amp source_event_id does not distinguish repeated session.start occurrences")
	}
	if !strings.Contains(text, `basePayload("session.start", threadID, ctx, "start", false)`) {
		t.Fatal("Amp session.start incorrectly inherits a cached turn/message ID")
	}
}

func TestAMPGuidanceDiscoveryUsesFallbacksHierarchyAndOnDemandSubtrees(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, "projects", "repo")
	nested := filepath.Join(workspace, "services", "api")
	ignored := filepath.Join(workspace, "node_modules", "dependency")
	for _, dir := range []string{nested, ignored} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(home, "AGENT.md"):       "home fallback",
		filepath.Join(workspace, "CLAUDE.md"): "workspace fallback",
		filepath.Join(nested, "AGENTS.md"):    "scoped",
		filepath.Join(ignored, "AGENTS.md"):   "ignored dependency",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	paths := ampWorkspaceAgentsPaths(SetupOpts{WorkspaceDir: workspace})
	for _, want := range []string{
		filepath.Join(workspace, "CLAUDE.md"),
		filepath.Join(home, "AGENT.md"),
	} {
		if !containsString(paths, want) {
			t.Errorf("guidance paths=%v missing %q", paths, want)
		}
	}
	if containsString(paths, filepath.Join(nested, "AGENTS.md")) {
		t.Fatalf("workspace capability discovery eagerly crawled a subtree: %v", paths)
	}
	if containsString(paths, filepath.Join(ignored, "AGENTS.md")) {
		t.Fatalf("dependency subtree was traversed: %v", paths)
	}
	if containsString(paths, filepath.Join(filepath.Dir(home), "AGENTS.md")) {
		t.Fatalf("ancestor lookup escaped HOME: %v", paths)
	}

	scoped := ampWorkspaceAgentsPaths(SetupOpts{WorkspaceDir: nested})
	for _, want := range []string{
		filepath.Join(nested, "AGENTS.md"),
		filepath.Join(workspace, "CLAUDE.md"),
		filepath.Join(home, "AGENT.md"),
	} {
		if !containsString(scoped, want) {
			t.Errorf("scoped guidance paths=%v missing %q", scoped, want)
		}
	}
}

func TestAMPContractCapabilitiesAndCorrelation(t *testing.T) {
	conn := NewAMPConnector()
	opts := SetupOpts{WorkspaceDir: filepath.Join(t.TempDir(), "workspace"), APIAddr: "127.0.0.1:18970"}
	caps := conn.Capabilities(opts)
	if !caps.Hooks.CanBlock || !caps.Hooks.CanAskNative || !caps.Hooks.SupportsFailClosed {
		t.Fatalf("hook capabilities=%+v", caps.Hooks)
	}
	if !eventInProfile("tool.call", caps.Hooks.BlockEvents) || !eventInProfile("tool.call", caps.Hooks.AskEvents) {
		t.Fatalf("tool.call missing from block/ask events: %+v", caps.Hooks)
	}
	if !caps.MCP.Supported || !caps.MCP.DiscoveryOnly || len(caps.MCP.WritePaths) != 0 {
		t.Fatalf("MCP capability must be read-only discovery: %+v", caps.MCP)
	}
	if !caps.Skills.Supported || len(caps.Skills.WritePaths) != 1 {
		t.Fatalf("skills capability=%+v", caps.Skills)
	}
	if !caps.Plugins.Supported || !caps.Plugins.DiscoveryOnly ||
		!caps.Rules.Supported || !caps.Rules.DiscoveryOnly ||
		!caps.Agents.Supported || !caps.Agents.DiscoveryOnly {
		t.Fatalf("component capabilities incomplete: %+v", caps)
	}
	if caps.Telemetry.NativeOTLP || len(caps.Telemetry.HookSignals) != 3 {
		t.Fatalf("telemetry capability=%+v", caps.Telemetry)
	}

	profile := conn.HookProfile(opts)
	if profile.ContractID != "amp-plugin-v1" || profile.SupportsTraceparent || profile.NativeOTLP != nil {
		t.Fatalf("profile=%+v", profile)
	}
	if profile.ResponseFieldName != "" {
		t.Fatalf("ResponseFieldName=%q want top-level unified response", profile.ResponseFieldName)
	}
	if got := profile.Respond(HookRespondInput{
		Req:       HookProfileRequest{ConnectorName: "amp", HookEventName: "tool.call", ToolName: "shell"},
		Action:    "confirm",
		RawAction: "confirm",
		Reason:    "approval required",
		Caps:      profile.Capabilities,
	}); got.FieldName != "" || got.Output != nil {
		t.Fatalf("Amp response should use top-level action: %+v", got)
	}

	spec := profile.Correlation
	if spec.ProfileVersion != CorrelationProfileAMPV1 ||
		spec.Completeness.Session != CorrelationCompletenessComplete ||
		spec.Completeness.Turn != CorrelationCompletenessComplete ||
		spec.Completeness.Tool != CorrelationCompletenessComplete {
		t.Fatalf("correlation spec=%+v", spec)
	}
	if _, ok := spec.HookValue(map[string]interface{}{"thread_id": "T-child"}, CorrelationTargetParentSession); ok {
		t.Fatal("Amp thread ID must not synthesize parent-child lineage")
	}
}

func TestAMPSkillCapabilityPathsHonorSettingsAndClaudePluginCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, "repo")
	settingsDir := filepath.Join(workspace, ".amp")
	cacheSkills := filepath.Join(
		home,
		".claude",
		"plugins",
		"cache",
		"marketplace",
		"review-plugin",
		"1.2.3",
		"skills",
	)
	for _, dir := range []string{settingsDir, cacheSkills} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	settingsPath := filepath.Join(settingsDir, "settings.jsonc")
	enabled := `{
	  // Relative additions are resolved from the pinned workspace.
	  "amp.skills.path": "team-skills",
	  "amp.skills.disableClaudeCodeSkills": false,
	}`
	if err := os.WriteFile(settingsPath, []byte(enabled), 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewAMPConnector()
	opts := SetupOpts{WorkspaceDir: workspace}
	readPaths := conn.Capabilities(opts).Skills.ReadPaths
	for _, want := range []string{
		filepath.Join(workspace, "team-skills"),
		filepath.Join(workspace, ".claude", "skills"),
		filepath.Join(home, ".claude", "skills"),
		cacheSkills,
	} {
		if !containsString(readPaths, want) {
			t.Errorf("enabled Amp skill paths=%v missing %q", readPaths, want)
		}
	}

	disabled := `{
	  "amp.skills.path": "team-skills",
	  "amp.skills.disableClaudeCodeSkills": true
	}`
	if err := os.WriteFile(settingsPath, []byte(disabled), 0o600); err != nil {
		t.Fatal(err)
	}
	readPaths = conn.Capabilities(opts).Skills.ReadPaths
	if !containsString(readPaths, filepath.Join(workspace, "team-skills")) {
		t.Fatalf("disabled Amp skill paths lost configured root: %v", readPaths)
	}
	for _, forbidden := range []string{
		filepath.Join(workspace, ".claude", "skills"),
		filepath.Join(home, ".claude", "skills"),
		cacheSkills,
	} {
		if containsString(readPaths, forbidden) {
			t.Fatalf("disabled Amp skill paths=%v retained Claude-compatible root %q", readPaths, forbidden)
		}
	}
}

func TestAMPSettingsReaderRejectsSymlinkAndOversize(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.json")
		link := filepath.Join(root, "settings.json")
		if err := os.WriteFile(
			target,
			[]byte(`{"amp.skills.disableClaudeCodeSkills":true}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, ok := readAMPSettingsDocument(link); ok {
			t.Fatal("Amp settings reader followed a symlink")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.json")
		if err := os.WriteFile(path, make([]byte, ampSettingsReadLimit+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := readAMPSettingsDocument(path); ok {
			t.Fatalf("Amp settings reader accepted a file larger than %d bytes", ampSettingsReadLimit)
		}
	})
}

func TestReadBoundedAMPDirectoryEnforcesRequestedCap(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"zeta", "alpha", "middle", "omega"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := readBoundedAMPDirectory(root, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("bounded entries=%d want 2", len(entries))
	}
	if strings.ToLower(entries[0].Name()) > strings.ToLower(entries[1].Name()) {
		t.Fatalf("bounded entries are not sorted: %q, %q", entries[0].Name(), entries[1].Name())
	}
}

func TestExpandAMPSkillPathAcceptsDocumentedTildeSlashOnEveryOS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	want := filepath.Join(home, "team", "skills")
	for _, raw := range []string{"~/team/skills", `~\team\skills`} {
		if got := expandAMPSkillPath(raw, SetupOpts{}); got != want {
			t.Errorf("expandAMPSkillPath(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestAMPWindowsIsSupportedAndUsesProfileConfigLayout(t *testing.T) {
	if support := ConnectorSupportOnOS("amp", "windows"); support.Status != PlatformSupported {
		t.Fatalf("Windows support=%+v", support)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	previous := AMPPluginPathOverride
	AMPPluginPathOverride = ""
	t.Cleanup(func() { AMPPluginPathOverride = previous })
	if got, want := ampPluginPath(SetupOpts{}), filepath.Join(home, ".config", "amp", "plugins", "defenseclaw.ts"); got != want {
		t.Fatalf("ampPluginPath=%q want %q", got, want)
	}
}

func TestAMPPluginPathUsesExplicitLifecycleConfigHome(t *testing.T) {
	profile := t.TempDir()
	t.Setenv("HOME", filepath.Join(profile, "unrelated-home"))
	t.Setenv("USERPROFILE", filepath.Join(profile, "unrelated-profile"))
	configHome := filepath.Join(profile, ".config", "amp")
	previous := AMPPluginPathOverride
	AMPPluginPathOverride = ""
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	opts := SetupOpts{ConfigHome: configHome}
	want := filepath.Join(configHome, "plugins", "defenseclaw.ts")
	if got := ampPluginPath(opts); got != want {
		t.Fatalf("ampPluginPath=%q want lifecycle-bound %q", got, want)
	}
	if got := NewAMPConnector().HookProfile(opts).Capabilities.ConfigPath; got != want {
		t.Fatalf("hook profile config path=%q want %q", got, want)
	}
}

func TestAMPHookEndpointRequiresBearerOnLoopbackAndRemote(t *testing.T) {
	conn := NewAMPConnector()
	conn.SetCredentials("amp-scoped-token", "master-token")

	for _, tc := range []struct {
		name       string
		remoteAddr string
		bearer     string
		want       bool
	}{
		{name: "loopback scoped", remoteAddr: "127.0.0.1:4321", bearer: "amp-scoped-token", want: true},
		{name: "loopback master", remoteAddr: "127.0.0.1:4321", bearer: "master-token", want: true},
		{name: "loopback missing", remoteAddr: "127.0.0.1:4321", bearer: "", want: false},
		{name: "loopback wrong", remoteAddr: "127.0.0.1:4321", bearer: "wrong-token", want: false},
		{name: "remote scoped", remoteAddr: "192.0.2.10:4321", bearer: "amp-scoped-token", want: true},
		{name: "remote wrong", remoteAddr: "192.0.2.10:4321", bearer: "wrong-token", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/amp/hook", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if got := conn.Authenticate(req); got != tc.want {
				t.Fatalf("Authenticate()=%t want %t", got, tc.want)
			}
		})
	}

	valid := httptest.NewRequest(http.MethodPost, "/api/v1/amp/hook", nil)
	valid.RemoteAddr = "127.0.0.1:4321"
	valid.Header.Set("Authorization", "Bearer amp-scoped-token")
	signals, err := conn.Route(valid, []byte(`{"hook_event_name":"tool.call"}`))
	if err != nil || signals.ConnectorName != "amp" || !signals.PassthroughMode {
		t.Fatalf("Route signals=%+v err=%v", signals, err)
	}
}

func TestAMPFailModeDefaultsClosed(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	previous := AMPPluginPathOverride
	AMPPluginPathOverride = filepath.Join(root, "defenseclaw.ts")
	t.Cleanup(func() { AMPPluginPathOverride = previous })
	conn := NewAMPConnector()
	if err := conn.Setup(context.Background(), SetupOpts{
		DataDir: filepath.Join(root, "data"),
		APIAddr: "127.0.0.1:18970",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(AMPPluginPathOverride)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `const DC_FAIL_MODE: string = "closed"`) {
		t.Fatal("unset hook fail mode did not render closed")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
