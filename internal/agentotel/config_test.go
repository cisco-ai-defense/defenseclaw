package agentotel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureClaudeDirectWritesOTELEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"),
		[]byte(`{"permissions":{"allow":["Bash(*)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ConfigureOpts{
		Tool:         ToolClaude,
		Endpoint:     "http://collector.internal:4318",
		Token:        "secret-token",
		HeaderName:   "Authorization",
		HeaderPrefix: "Bearer ",
		TenantID:     "t1",
		WorkspaceID:  "w1",
		AgentName:    "test-agent",
		Environment:  "ci",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := settings["permissions"]; !ok {
		t.Error("permissions key was lost")
	}

	env, ok := settings["env"].(map[string]interface{})
	if !ok {
		t.Fatal("env section missing")
	}

	checks := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY":        "1",
		"OTEL_EXPORTER_OTLP_PROTOCOL":         "http/protobuf",
		"OTEL_EXPORTER_OTLP_ENDPOINT":         "http://collector.internal:4318",
		"OTEL_EXPORTER_OTLP_HEADERS":          "Authorization=Bearer secret-token",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "http://collector.internal:4318/v1/traces",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://collector.internal:4318/v1/metrics",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    "http://collector.internal:4318/v1/logs",
		"OTEL_METRICS_EXPORTER":               "otlp",
		"OTEL_TRACES_EXPORTER":                "otlp",
		"OTEL_LOGS_EXPORTER":                  "otlp",
	}
	for key, want := range checks {
		got, ok := env[key].(string)
		if !ok || got != want {
			t.Errorf("env[%q] = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{
		"BETA_TRACING_ENDPOINT",
		"ENABLE_BETA_TRACING_DETAILED",
		"ENABLE_ENHANCED_TELEMETRY_BETA",
	} {
		if _, ok := env[key]; ok {
			t.Errorf("env[%q] should not be set in direct OTLP mode", key)
		}
	}

	attrs, _ := env["OTEL_RESOURCE_ATTRIBUTES"].(string)
	for _, want := range []string{
		"tenant_id=t1",
		"workspace_id=w1",
		"agent_name=test-agent",
		"wrapped_cli=claude",
	} {
		if !strings.Contains(attrs, want) {
			t.Errorf("resource attrs missing %q in %q", want, attrs)
		}
	}
}

func TestConfigureClaudeSetsBedrockWhenAWSHelperDetected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"userID":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws-bedrock-cc-creds.json"), []byte(`{"Credentials":{"AccessKeyId":"x"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"),
		[]byte(`{"env":{"awsCredentialExport":"cat ~/.aws-bedrock-cc-creds.json"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ConfigureOpts{
		Tool:       ToolClaude,
		SplunkHost: "us1",
		Token:      "splunk-token",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env := settings["env"].(map[string]interface{})
	if got := env["CLAUDE_CODE_USE_BEDROCK"]; got != "1" {
		t.Fatalf("CLAUDE_CODE_USE_BEDROCK = %v", got)
	}
}

func TestConfigureClaudeSplunkDirectBootstrapsLogs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	opts := ConfigureOpts{
		Tool:        ToolClaude,
		SplunkHost:  "app.us1.observability.splunkcloud.com",
		Token:       "splunk-token",
		Environment: "prod",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env := settings["env"].(map[string]interface{})

	if got := env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]; got != "https://ingest.us1.signalfx.com/v2/trace/otlp" {
		t.Fatalf("trace endpoint = %v", got)
	}
	if got := env["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]; got != "https://ingest.us1.signalfx.com/v2/datapoint/otlp" {
		t.Fatalf("metrics endpoint = %v", got)
	}
	if got := env["OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"]; got != "http/protobuf" {
		t.Fatalf("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL = %v", got)
	}
	if got := env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; got != "https://ingest.us1.signalfx.com/v1/logs" {
		t.Fatalf("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT = %v", got)
	}
	if got := env["OTEL_LOGS_EXPORTER"]; got != "otlp" {
		t.Fatalf("OTEL_LOGS_EXPORTER = %v", got)
	}
	if got := env["OTEL_EXPORTER_OTLP_HEADERS"]; got != "X-SF-Token=splunk-token" {
		t.Fatalf("OTEL_EXPORTER_OTLP_HEADERS = %v", got)
	}
	for _, key := range []string{
		"BETA_TRACING_ENDPOINT",
		"ENABLE_BETA_TRACING_DETAILED",
		"ENABLE_ENHANCED_TELEMETRY_BETA",
	} {
		if _, ok := env[key]; ok {
			t.Fatalf("%s should be absent in direct Splunk mode", key)
		}
	}
}

func TestUnconfigureClaudeRemovesOTELEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	initial := map[string]interface{}{
		"permissions": map[string]interface{}{"allow": []string{"Bash(*)"}},
		"env": map[string]interface{}{
			"BETA_TRACING_ENDPOINT":          "https://example.invalid",
			"CLAUDE_CODE_ENABLE_TELEMETRY":   "1",
			"ENABLE_BETA_TRACING_DETAILED":   "1",
			"ENABLE_ENHANCED_TELEMETRY_BETA": "1",
			"OTEL_EXPORTER_OTLP_ENDPOINT":    "http://127.0.0.1:4318",
			"OTEL_EXPORTER_OTLP_HEADERS":     "Authorization=Bearer keep-out",
			"OTEL_METRICS_EXPORTER":          "otlp",
			"MY_CUSTOM_VAR":                  "keep-me",
		},
	}
	data, _ := json.MarshalIndent(initial, "", "  ")
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Unconfigure(ToolClaude); err != nil {
		t.Fatalf("Unconfigure: %v", err)
	}

	after, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(after, &settings); err != nil {
		t.Fatal(err)
	}

	env, _ := settings["env"].(map[string]interface{})
	if _, ok := env["OTEL_EXPORTER_OTLP_ENDPOINT"]; ok {
		t.Error("OTEL_EXPORTER_OTLP_ENDPOINT should have been removed")
	}
	if _, ok := env["BETA_TRACING_ENDPOINT"]; ok {
		t.Error("BETA_TRACING_ENDPOINT should have been removed")
	}
	if _, ok := env["ENABLE_BETA_TRACING_DETAILED"]; ok {
		t.Error("ENABLE_BETA_TRACING_DETAILED should have been removed")
	}
	if _, ok := env["ENABLE_ENHANCED_TELEMETRY_BETA"]; ok {
		t.Error("ENABLE_ENHANCED_TELEMETRY_BETA should have been removed")
	}
	if _, ok := env["OTEL_EXPORTER_OTLP_HEADERS"]; ok {
		t.Error("OTEL_EXPORTER_OTLP_HEADERS should have been removed")
	}
	if _, ok := env["OTEL_METRICS_EXPORTER"]; ok {
		t.Error("OTEL_METRICS_EXPORTER should have been removed")
	}
	if v, ok := env["MY_CUSTOM_VAR"].(string); !ok || v != "keep-me" {
		t.Error("MY_CUSTOM_VAR should have been preserved")
	}
}

func TestConfigureCodexDirectWritesHeaders(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := "personality = \"pragmatic\"\nmodel = \"gpt-5.4\"\n"
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ConfigureOpts{
		Tool:         ToolCodex,
		Endpoint:     "http://collector.internal:4318",
		Token:        "token-1",
		HeaderName:   "Authorization",
		HeaderPrefix: "Bearer ",
		Environment:  "prod",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, `personality = "pragmatic"`) {
		t.Error("existing config was lost")
	}
	for _, want := range []string{
		`[otel]`,
		`endpoint = "http://collector.internal:4318/v1/logs"`,
		`endpoint = "http://collector.internal:4318/v1/metrics"`,
		`endpoint = "http://collector.internal:4318/v1/traces"`,
		`headers = { "Authorization" = "Bearer token-1" }`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("config missing %q", want)
		}
	}
}

func TestConfigureCodexSplunkDirectDisablesLogs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	opts := ConfigureOpts{
		Tool:       ToolCodex,
		SplunkHost: "us1",
		Token:      "splunk-token",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, `exporter = "none"`) {
		t.Fatal("logs exporter should be disabled in direct Splunk mode")
	}
	for _, want := range []string{
		`endpoint = "https://ingest.us1.signalfx.com/v2/datapoint/otlp"`,
		`endpoint = "https://ingest.us1.signalfx.com/v2/trace/otlp"`,
		`headers = { "X-SF-Token" = "splunk-token" }`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("config missing %q", want)
		}
	}
}

func TestConfigureCodexReplacesManagedBlockWithoutDuplicatingMarkers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `model = "gpt-5.4"

# BEGIN DEFENSECLAW OTEL CONFIG
[otel]
exporter = "none"
# END DEFENSECLAW OTEL CONFIG
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ConfigureOpts{
		Tool:        ToolCodex,
		SplunkHost:  "us1",
		Token:       "splunk-token",
		Environment: "prod",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if got := strings.Count(content, codexManagedBeginMarker); got != 1 {
		t.Fatalf("begin marker count = %d\n%s", got, content)
	}
	if got := strings.Count(content, codexManagedEndMarker); got != 1 {
		t.Fatalf("end marker count = %d\n%s", got, content)
	}
}

func TestConfigureCodexRejectsUnmanagedOtelSection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `model = "gpt-5.4"

[otel]
environment = "custom"
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Configure(ConfigureOpts{
		Tool:       ToolCodex,
		SplunkHost: "us1",
		Token:      "splunk-token",
	})
	if err == nil || !strings.Contains(err.Error(), "unmanaged [otel] section") {
		t.Fatalf("Configure error = %v", err)
	}
}

func TestConfigureAllWritesBothFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	opts := ConfigureOpts{
		Tool:        ToolAll,
		SplunkHost:  "us1",
		Token:       "splunk-token",
		Environment: "ci",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatalf("Claude config missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); err != nil {
		t.Fatalf("Codex config missing: %v", err)
	}
}

func TestConfigureAllAppliesToolSpecificOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	opts := ConfigureOpts{
		Tool:              ToolAll,
		SplunkHost:        "us1",
		Token:             "splunk-token",
		Environment:       "shared-env",
		AgentName:         "shared-agent",
		ClaudeAgentName:   "claude-agent",
		ClaudeEnvironment: "claude-env",
		CodexAgentName:    "codex-agent",
		CodexEnvironment:  "codex-env",
		ClaudeWorkspaceID: "claude-workspace",
		CodexWorkspaceID:  "codex-workspace",
		ClaudeTenantID:    "claude-tenant",
		CodexTenantID:     "codex-tenant",
	}
	if err := Configure(opts); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	claudeData, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var claudeSettings map[string]interface{}
	if err := json.Unmarshal(claudeData, &claudeSettings); err != nil {
		t.Fatal(err)
	}
	claudeEnv := claudeSettings["env"].(map[string]interface{})
	attrs, _ := claudeEnv["OTEL_RESOURCE_ATTRIBUTES"].(string)
	for _, want := range []string{
		"agent_name=claude-agent",
		"deployment.environment=claude-env",
		"tenant_id=claude-tenant",
		"workspace_id=claude-workspace",
		"wrapped_cli=claude",
	} {
		if !strings.Contains(attrs, want) {
			t.Fatalf("Claude attrs missing %q in %q", want, attrs)
		}
	}

	codexData, err := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	codexConfig := string(codexData)
	if !strings.Contains(codexConfig, `environment = "codex-env"`) {
		t.Fatalf("Codex config missing codex-specific environment:\n%s", codexConfig)
	}
}

func TestConfigureRejectsIrrelevantToolSpecificOverrides(t *testing.T) {
	err := Configure(ConfigureOpts{
		Tool:            ToolCodex,
		SplunkHost:      "us1",
		Token:           "splunk-token",
		ClaudeAgentName: "claude-only",
	})
	if err == nil || !strings.Contains(err.Error(), "Codex-specific") && !strings.Contains(err.Error(), "Claude-specific") {
		t.Fatalf("Configure error = %v", err)
	}
}

func TestUnconfigureCodexRemovesOTELSection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `personality = "pragmatic"

# BEGIN DEFENSECLAW OTEL CONFIG
[otel]
exporter = "none"
# END DEFENSECLAW OTEL CONFIG
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Unconfigure(ToolCodex); err != nil {
		t.Fatalf("Unconfigure: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	result := string(data)

	if strings.Contains(result, "[otel]") {
		t.Error("[otel] section should have been removed")
	}
	if !strings.Contains(result, `personality = "pragmatic"`) {
		t.Error("existing config was lost")
	}
}

func TestStripManagedTOMLBlock(t *testing.T) {
	input := `key1 = "val1"

# BEGIN DEFENSECLAW OTEL CONFIG
[otel]
exporter = "foo"
# END DEFENSECLAW OTEL CONFIG

[other]
x = 1
`
	got := stripManagedTOMLBlock(input, codexManagedBeginMarker, codexManagedEndMarker)
	if strings.Contains(got, codexManagedBeginMarker) || strings.Contains(got, "[otel]") {
		t.Error("managed block should be removed")
	}
	if !strings.Contains(got, "[other]") {
		t.Error("other section should remain")
	}
	if !strings.Contains(got, `key1 = "val1"`) {
		t.Error("top-level key should remain")
	}
}

func TestHasTOMLSection(t *testing.T) {
	if !hasTOMLSection("[otel]\nexporter = \"none\"\n", "otel") {
		t.Fatal("expected otel section to be found")
	}
	if hasTOMLSection("model = \"gpt-5.4\"\n", "otel") {
		t.Fatal("did not expect otel section to be found")
	}
}

func TestNormalizeOTLPBaseEndpointTrimsSignalSuffix(t *testing.T) {
	base, warning, err := normalizeOTLPBaseEndpoint("http://collector:4318/v1/traces")
	if err != nil {
		t.Fatalf("normalizeOTLPBaseEndpoint: %v", err)
	}
	if base != "http://collector:4318" {
		t.Fatalf("base = %q", base)
	}
	if !strings.Contains(warning, "trimmed") {
		t.Fatalf("warning = %q", warning)
	}
}

func TestBuildAuthHeaderDefaults(t *testing.T) {
	headerName, headerValue := buildAuthHeader(ConfigureOpts{Token: "abc"}, false)
	if headerName != "Authorization" {
		t.Fatalf("headerName = %q", headerName)
	}
	if headerValue != "Bearer abc" {
		t.Fatalf("headerValue = %q", headerValue)
	}

	headerName, headerValue = buildAuthHeader(ConfigureOpts{Token: "abc"}, true)
	if headerName != "X-SF-Token" {
		t.Fatalf("headerName = %q", headerName)
	}
	if headerValue != "abc" {
		t.Fatalf("headerValue = %q", headerValue)
	}
}

func TestConfigureRejectsConflictingDeprecatedToken(t *testing.T) {
	err := Configure(ConfigureOpts{
		Tool:                  ToolClaude,
		Endpoint:              "http://collector.internal:4318",
		Token:                 "token-a",
		DeprecatedSplunkToken: "token-b",
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting values") {
		t.Fatalf("Configure error = %v", err)
	}
}

func TestConfigEnvValueFallsBackToOSEnv(t *testing.T) {
	t.Setenv("CLAUDE_CODE_USE_BEDROCK", "1")
	if got := configEnvValue(map[string]interface{}{}, "CLAUDE_CODE_USE_BEDROCK"); got != "1" {
		t.Fatalf("configEnvValue fallback = %q", got)
	}
}

func TestHasClaudeFirstPartyAuthParsesJSONKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	if err := os.WriteFile(path, []byte(`{"profile":{"oauthAccount":{"email":"user@example.com"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasClaudeFirstPartyAuth(path) {
		t.Fatal("expected parsed oauthAccount key to be detected")
	}
}

func TestSettingsEnableClaudeBedrockParsesJSONKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"env":{"awsCredentialExport":"cat ~/.aws-bedrock-cc-creds.json"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if !settingsEnableClaudeBedrock(path) {
		t.Fatal("expected awsCredentialExport key to be detected")
	}
}

func TestDeriveIngestHostFromAppHost(t *testing.T) {
	host, warning, err := deriveIngestHost("app.us1.observability.splunkcloud.com")
	if err != nil {
		t.Fatalf("deriveIngestHost: %v", err)
	}
	if host != "ingest.us1.signalfx.com" {
		t.Fatalf("host = %q, want ingest.us1.signalfx.com", host)
	}
	if !strings.Contains(warning, "derived ingest host") {
		t.Fatalf("warning = %q", warning)
	}
}

func TestMergeResourceAttributes(t *testing.T) {
	got := mergeResourceAttributes("service.name=codex,team=platform", map[string]string{
		"tenant_id":    "tenant-1",
		"workspace_id": "workspace-a",
		"agent_name":   "demo agent",
	})
	for _, want := range []string{
		"service.name=codex",
		"team=platform",
		"tenant_id=tenant-1",
		"workspace_id=workspace-a",
		"agent_name=demo%20agent",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("merged attrs missing %q in %q", want, got)
		}
	}
}
