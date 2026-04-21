package agentotel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildClaudeRunSpecSetsRuntimeEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws-bedrock-cc-creds.json"), []byte(`{"token":"bedrock"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{
  "permissions": {
    "allow": ["Read"]
  },
  "env": {
    "EXISTING_KEY": "existing-value"
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := ConfigureOpts{
		Tool:        ToolClaude,
		SplunkHost:  "us1",
		Token:       "splunk-token",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-claude",
		AgentName:   "claude-desktop",
		Environment: "claude-dev",
	}
	target, err := resolveTelemetryTarget(opts)
	if err != nil {
		t.Fatalf("resolveTelemetryTarget: %v", err)
	}

	spec, err := buildRunSpec(opts, "", []string{"-p", "--model", "haiku"}, target)
	if err != nil {
		t.Fatalf("buildRunSpec: %v", err)
	}
	if spec.binary != "claude" {
		t.Fatalf("binary = %q", spec.binary)
	}
	if got := strings.Join(spec.args, " "); got != "-p --model haiku" {
		t.Fatalf("args = %q", got)
	}

	env := envSliceToMap(spec.env)
	if got := env["HOME"]; got != home {
		t.Fatalf("HOME = %q, want %q", got, home)
	}
	if got := spec.binary; got != "claude" {
		t.Fatalf("binary = %q", got)
	}
	if got, ok := env["EXISTING_KEY"]; !ok || got != "existing-value" {
		t.Fatalf("EXISTING_KEY = %q", got)
	}
	if _, ok := env["permissions"]; ok {
		t.Fatal("unexpected settings JSON key leaked into env")
	}
	if got := env["CLAUDE_CODE_USE_BEDROCK"]; got != "1" {
		t.Fatalf("CLAUDE_CODE_USE_BEDROCK = %q", got)
	}
	if got := env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]; got != "https://ingest.us1.signalfx.com/v2/trace/otlp" {
		t.Fatalf("trace endpoint = %q", got)
	}
	if got := env["OTEL_EXPORTER_OTLP_TRACES_HEADERS"]; got != "X-SF-Token=splunk-token" {
		t.Fatalf("trace headers = %q", got)
	}
	if got := env["OTEL_LOGS_EXPORTER"]; got != "otlp" {
		t.Fatalf("OTEL_LOGS_EXPORTER = %q", got)
	}
	attrs := env["OTEL_RESOURCE_ATTRIBUTES"]
	for _, want := range []string{
		"tenant_id=tenant-a",
		"workspace_id=workspace-claude",
		"agent_name=claude-desktop",
		"deployment.environment=claude-dev",
		"wrapped_cli=claude",
	} {
		if !strings.Contains(attrs, want) {
			t.Fatalf("missing %q in %q", want, attrs)
		}
	}
}

func TestBuildCodexRunSpecSetsRuntimeEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	opts := ConfigureOpts{
		Tool:        ToolCodex,
		SplunkHost:  "us1",
		Token:       "splunk-token",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-codex",
		AgentName:   "codex-desktop",
		Environment: "codex-dev",
	}
	target, err := resolveTelemetryTarget(opts)
	if err != nil {
		t.Fatalf("resolveTelemetryTarget: %v", err)
	}

	spec, err := buildRunSpec(opts, "", []string{"exec", "--skip-git-repo-check", "--json", "Reply with ok only"}, target)
	if err != nil {
		t.Fatalf("buildRunSpec: %v", err)
	}
	if spec.binary != "codex" {
		t.Fatalf("binary = %q", spec.binary)
	}
	args := strings.Join(spec.args, " ")
	for _, want := range []string{
		`exec -c otel.environment="codex-dev"`,
		`-c otel.metrics_exporter={ "otlp-http" = { endpoint = "https://ingest.us1.signalfx.com/v2/datapoint/otlp", protocol = "binary", headers = { "X-SF-Token" = "splunk-token" } } }`,
		`-c otel.trace_exporter={ "otlp-http" = { endpoint = "https://ingest.us1.signalfx.com/v2/trace/otlp", protocol = "binary", headers = { "X-SF-Token" = "splunk-token" } } }`,
		`--skip-git-repo-check --json Reply with ok only`,
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("args missing %q in %q", want, args)
		}
	}
	env := envSliceToMap(spec.env)
	if got := env["HOME"]; got != home {
		t.Fatalf("HOME = %q, want %q", got, home)
	}
	if got := env["OTEL_EXPORTER_OTLP_HEADERS"]; got != "X-SF-Token=splunk-token" {
		t.Fatalf("OTEL_EXPORTER_OTLP_HEADERS = %q", got)
	}
	for _, want := range []string{
		"https://ingest.us1.signalfx.com/v2/trace/otlp",
		"https://ingest.us1.signalfx.com/v2/datapoint/otlp",
	} {
		if !strings.Contains(strings.Join(spec.env, "\n"), want) {
			t.Fatalf("env missing %q in:\n%s", want, strings.Join(spec.env, "\n"))
		}
	}
	if strings.Contains(strings.Join(spec.env, "\n"), "https://ingest.us1.signalfx.com/v1/logs") {
		t.Fatalf("did not expect direct Codex logs endpoint in:\n%s", strings.Join(spec.env, "\n"))
	}
	attrs := env["OTEL_RESOURCE_ATTRIBUTES"]
	for _, want := range []string{
		"tenant_id=tenant-a",
		"workspace_id=workspace-codex",
		"agent_name=codex-desktop",
		"deployment.environment=codex-dev",
		"wrapped_cli=codex",
	} {
		if !strings.Contains(attrs, want) {
			t.Fatalf("missing %q in %q", want, attrs)
		}
	}
}

func TestRunLaunchesBinaryWithInjectedTelemetry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	outFile := filepath.Join(home, "capture.txt")
	script := filepath.Join(home, "fake-codex.sh")
	scriptBody := "#!/bin/sh\n" +
		"printf 'ARGS=%s\\n' \"$*\" > \"$CAPTURE_FILE\"\n" +
		"printf 'TRACE=%s\\n' \"$OTEL_EXPORTER_OTLP_TRACES_ENDPOINT\" >> \"$CAPTURE_FILE\"\n" +
		"printf 'METRICS=%s\\n' \"$OTEL_EXPORTER_OTLP_METRICS_ENDPOINT\" >> \"$CAPTURE_FILE\"\n" +
		"printf 'LOGS=%s\\n' \"$OTEL_EXPORTER_OTLP_LOGS_ENDPOINT\" >> \"$CAPTURE_FILE\"\n" +
		"printf 'ATTRS=%s\\n' \"$OTEL_RESOURCE_ATTRIBUTES\" >> \"$CAPTURE_FILE\"\n"
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPTURE_FILE", outFile)

	opts := RunOpts{
		ConfigureOpts: ConfigureOpts{
			Tool:        ToolCodex,
			SplunkHost:  "us1",
			Token:       "splunk-token",
			TenantID:    "tenant-a",
			WorkspaceID: "workspace-codex",
			AgentName:   "codex-desktop",
			Environment: "codex-dev",
		},
		Binary: script,
	}
	if err := Run(context.Background(), opts, []string{"exec", "--skip-git-repo-check", "--json", "Reply with ok only"}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{
		`ARGS=exec -c otel.environment="codex-dev"`,
		`otel.metrics_exporter={ "otlp-http" = { endpoint = "https://ingest.us1.signalfx.com/v2/datapoint/otlp", protocol = "binary", headers = { "X-SF-Token" = "splunk-token" } } }`,
		`otel.trace_exporter={ "otlp-http" = { endpoint = "https://ingest.us1.signalfx.com/v2/trace/otlp", protocol = "binary", headers = { "X-SF-Token" = "splunk-token" } } }`,
		`--skip-git-repo-check --json Reply with ok only`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("captured args missing %q:\n%s", want, content)
		}
	}
	for _, want := range []string{
		`TRACE=https://ingest.us1.signalfx.com/v2/trace/otlp`,
		`METRICS=https://ingest.us1.signalfx.com/v2/datapoint/otlp`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("captured env missing %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, `LOGS=https://ingest.us1.signalfx.com/v1/logs`) {
		t.Fatalf("did not expect direct Codex logs endpoint:\n%s", content)
	}
	for _, want := range []string{
		"tenant_id=tenant-a",
		"workspace_id=workspace-codex",
		"agent_name=codex-desktop",
		"deployment.environment=codex-dev",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("captured attrs missing %q:\n%s", want, content)
		}
	}
}
