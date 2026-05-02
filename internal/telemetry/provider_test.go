// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func disabledCfg() *config.Config {
	return &config.Config{
		OTel: config.OTelConfig{
			Enabled: false,
		},
		Claw: config.ClawConfig{
			Mode:    config.ClawOpenClaw,
			HomeDir: "/tmp/test-claw",
		},
		Gateway: config.GatewayConfig{
			Host: "127.0.0.1",
			Port: 18789,
		},
		Environment: "test",
	}
}

func TestNewProvider_Disabled(t *testing.T) {
	p, err := NewProvider(context.Background(), disabledCfg(), "test")
	if err != nil {
		t.Fatalf("NewProvider disabled: %v", err)
	}
	if p.Enabled() {
		t.Error("expected disabled provider")
	}
	if p.LogsEnabled() {
		t.Error("expected logs disabled")
	}
	if p.TracesEnabled() {
		t.Error("expected traces disabled")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown disabled: %v", err)
	}
}

func TestNewProvider_NilSafe(t *testing.T) {
	var p *Provider

	if p.Enabled() {
		t.Error("nil provider should not be enabled")
	}
	if p.LogsEnabled() {
		t.Error("nil provider logs should not be enabled")
	}
	if p.TracesEnabled() {
		t.Error("nil provider traces should not be enabled")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil shutdown: %v", err)
	}
}

func TestDisabledProvider_EmitLifecycleEvent_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitLifecycleEvent("block", "test-skill", "skill", "test reason", "HIGH", nil)
}

func TestDisabledProvider_EmitScanResult_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	result := &scanner.ScanResult{
		Scanner:   "test-scanner",
		Target:    "/tmp/test",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	p.EmitScanResult(result, "scan-123", "skill", "clean")
}

func TestDisabledProvider_EmitRuntimeAlert_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitRuntimeAlert(AlertDangerousCommand, "HIGH", SourceLocalPattern,
		"test alert", nil, nil, "", "")
}

func TestDisabledProvider_StartToolSpan_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"cmd":"ls"}`), false, "", "builtin", "",
		ToolSpanContext{})
	if span != nil {
		t.Error("span should be nil when disabled")
	}
	if ctx == nil {
		t.Error("context should not be nil")
	}
}

func TestStartToolSpan_RawArgsOnlyWhenRedactionDisabled(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	p, exp := newTracingProvider(t)
	_, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"secret":"abc123"}`), false, "", "builtin", "",
		ToolSpanContext{})
	p.EndToolSpan(span, 0, 0, time.Now(), "shell", "builtin")
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if _, ok := attrByKey(spans[0].Attributes, "defenseclaw.tool.args"); ok {
		t.Fatal("raw tool args were exported while redaction was enabled")
	}

	redaction.SetDisableAll(true)
	p, exp = newTracingProvider(t)
	_, span = p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"secret":"abc123"}`), false, "", "builtin", "",
		ToolSpanContext{})
	p.EndToolSpan(span, 0, 0, time.Now(), "shell", "builtin")
	spans = exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d raw-mode spans, want 1", len(spans))
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.tool.args"); !ok || got.AsString() != `{"secret":"abc123"}` {
		t.Fatalf("raw tool args attr = %q ok=%v, want exact JSON", got.AsString(), ok)
	}
}

func TestStartToolSpan_EmitsSessionToolPolicyCorrelation(t *testing.T) {
	p, exp := newTracingProvider(t)
	_, span := p.StartToolSpan(context.Background(), "shell", "running",
		json.RawMessage(`{"cmd":"rg -n observed_agent_session ."}`), false, "", "builtin", "",
		ToolSpanContext{
			ToolID:         "tool-123",
			SessionID:      "session-123",
			RunID:          "run-123",
			DestinationApp: "builtin",
			PolicyID:       "policy-allow-shell",
			AgentName:      "codex",
			AgentID:        "openai_codex",
		})
	p.EndToolSpan(span, 0, 0, time.Now(), "shell", "builtin")

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}

	for key, want := range map[string]string{
		"gen_ai.tool.call.id":         "tool-123",
		"gen_ai.conversation.id":      "session-123",
		"defenseclaw.run.id":          "run-123",
		"defenseclaw.destination.app": "builtin",
		"defenseclaw.policy.id":       "policy-allow-shell",
		"gen_ai.agent.name":           "codex",
		"gen_ai.agent.id":             "openai_codex",
		"gen_ai.operation.name":       "execute_tool",
		"gen_ai.tool.name":            "shell",
	} {
		got, ok := attrByKey(spans[0].Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s = %q ok=%v, want %q", key, got.AsString(), ok, want)
		}
	}
}

func TestStartApprovalSpan_RawCommandOnlyWhenRedactionDisabled(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	p, exp := newTracingProvider(t)
	_, span := p.StartApprovalSpan(context.Background(), "approval-1", "/usr/bin/curl",
		[]string{"-H", "Authorization: Bearer secret"}, "/tmp/work",
		ToolSpanContext{})
	p.EndApprovalSpan(span, "approved", "ok", false, false)
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	for _, key := range []string{"defenseclaw.approval.command", "defenseclaw.approval.argv", "defenseclaw.approval.cwd"} {
		if _, ok := attrByKey(spans[0].Attributes, key); ok {
			t.Fatalf("%s exported while redaction was enabled", key)
		}
	}

	redaction.SetDisableAll(true)
	p, exp = newTracingProvider(t)
	_, span = p.StartApprovalSpan(context.Background(), "approval-1", "/usr/bin/curl",
		[]string{"-H", "Authorization: Bearer secret"}, "/tmp/work",
		ToolSpanContext{})
	p.EndApprovalSpan(span, "approved", "ok", false, false)
	spans = exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d raw-mode spans, want 1", len(spans))
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.approval.command"); !ok || got.AsString() != "/usr/bin/curl" {
		t.Fatalf("raw command attr = %q ok=%v, want /usr/bin/curl", got.AsString(), ok)
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.approval.argv"); !ok {
		t.Fatal("raw argv attr missing in raw mode")
	} else if argv := got.AsStringSlice(); len(argv) != 2 || argv[1] != "Authorization: Bearer secret" {
		t.Fatalf("raw argv attr = %#v, want original argv", argv)
	}
	if got, ok := attrByKey(spans[0].Attributes, "defenseclaw.approval.cwd"); !ok || got.AsString() != "/tmp/work" {
		t.Fatalf("raw cwd attr = %q ok=%v, want /tmp/work", got.AsString(), ok)
	}
}

func TestDisabledProvider_Metrics_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx := context.Background()
	p.RecordScan(ctx, "test", "skill", "clean", 100, map[string]int{"HIGH": 1})
	p.RecordToolCall(ctx, "shell", "builtin", false)
	p.RecordToolDuration(ctx, "shell", "builtin", 50)
	p.RecordToolError(ctx, "shell", 1)
	p.RecordApproval(ctx, "approved", true, false)
	p.RecordLLMTokens(ctx, "chat", "openai", "gpt-4", "", "", 100, 200)
	p.RecordLLMDuration(ctx, "chat", "openai", "gpt-4", "", "", 0.5)
	p.RecordAlert(ctx, "dangerous-command", "HIGH", "local-pattern")
	p.RecordGuardrailEvaluation(ctx, "ai-defense", "block")
	p.RecordGuardrailLatency(ctx, "ai-defense", 100)
}

func TestExpandHeaders(t *testing.T) {
	t.Setenv("TEST_TOKEN", "abc123")

	headers := map[string]string{
		"X-SF-TOKEN": "${TEST_TOKEN}",
		"X-Static":   "static-value",
	}

	expanded := expandHeaders(headers)
	if expanded["X-SF-TOKEN"] != "abc123" {
		t.Errorf("expected abc123, got %s", expanded["X-SF-TOKEN"])
	}
	if expanded["X-Static"] != "static-value" {
		t.Errorf("expected static-value, got %s", expanded["X-Static"])
	}
}

func TestExpandHeaders_MissingEnv(t *testing.T) {
	headers := map[string]string{
		"X-TOKEN": "${NONEXISTENT_VAR_12345}",
	}
	expanded := expandHeaders(headers)
	if expanded["X-TOKEN"] != "" {
		t.Errorf("expected empty for missing env, got %q", expanded["X-TOKEN"])
	}
}

// TestExpandHeaders_NoAutoInjection enforces the post-decoupling
// contract: expandHeaders is vendor-neutral. Legacy builds auto-injected
// X-SF-Token from SPLUNK_ACCESS_TOKEN; that coupling was removed so the
// telemetry stack is a plain OTLP client. Operators who need a Splunk
// token now put it in cfg.OTel.Headers or OTEL_EXPORTER_OTLP_HEADERS.
func TestExpandHeaders_NoAutoInjection(t *testing.T) {
	t.Setenv("SPLUNK_ACCESS_TOKEN", "should-be-ignored")
	expanded := expandHeaders(map[string]string{})
	if _, ok := expanded["X-SF-Token"]; ok {
		t.Fatalf("expandHeaders must not auto-inject Splunk token, got %v", expanded)
	}
	if len(expanded) != 0 {
		t.Fatalf("expandHeaders should return empty map for empty input, got %v", expanded)
	}
}

func TestNewProvider_StandardOTLPEnvHTTPLogs(t *testing.T) {
	type requestInfo struct {
		path   string
		header string
	}
	reqC := make(chan requestInfo, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqC <- requestInfo{
			path:   r.URL.Path,
			header: r.Header.Get("X-Test"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-test=env-header")

	cfg := disabledCfg()
	cfg.OTel = config.OTelConfig{
		Enabled: true,
		Logs: config.OTelLogsConfig{
			Enabled: true,
		},
		Traces: config.OTelTracesConfig{
			Enabled: false,
		},
		Metrics: config.OTelMetricsConfig{
			Enabled: false,
		},
		Batch: config.OTelBatchConfig{
			MaxExportBatchSize: 1,
			ScheduledDelayMs:   10,
			MaxQueueSize:       8,
		},
	}

	p, err := NewProvider(context.Background(), cfg, "test")
	if err != nil {
		t.Fatalf("NewProvider err=%v", err)
	}

	p.EmitGatewayEvent(gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventDiagnostic,
		Severity:  gatewaylog.SeverityInfo,
		Diagnostic: &gatewaylog.DiagnosticPayload{
			Component: "telemetry-test",
			Message:   "env-path",
		},
	})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown err=%v", err)
	}

	select {
	case got := <-reqC:
		if got.path != "/v1/logs" {
			t.Fatalf("request path=%q want /v1/logs", got.path)
		}
		if got.header != "env-header" {
			t.Fatalf("X-Test header=%q want env-header", got.header)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for OTLP logs request")
	}
}

func TestResolveValue(t *testing.T) {
	tests := []struct {
		name   string
		signal string
		global string
		want   string
	}{
		{"signal set", "signal-endpoint", "global-endpoint", "signal-endpoint"},
		{"signal empty", "", "global-endpoint", "global-endpoint"},
		{"both empty", "", "", ""},
		{"signal set global empty", "signal-endpoint", "", "signal-endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveValue(tt.signal, tt.global)
			if got != tt.want {
				t.Errorf("resolveValue(%q, %q) = %q, want %q", tt.signal, tt.global, got, tt.want)
			}
		})
	}
}

func TestTemporalitySelector(t *testing.T) {
	kinds := []sdkmetric.InstrumentKind{
		sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindHistogram,
		sdkmetric.InstrumentKindGauge,
		sdkmetric.InstrumentKindObservableCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter,
		sdkmetric.InstrumentKindObservableGauge,
	}

	t.Run("delta", func(t *testing.T) {
		sel := temporalitySelector("delta")
		for _, k := range kinds {
			if got := sel(k); got != metricdata.DeltaTemporality {
				t.Errorf("temporalitySelector(\"delta\")(%v) = %v, want Delta", k, got)
			}
		}
	})

	t.Run("empty defaults to delta", func(t *testing.T) {
		sel := temporalitySelector("")
		for _, k := range kinds {
			if got := sel(k); got != metricdata.DeltaTemporality {
				t.Errorf("temporalitySelector(\"\")(%v) = %v, want Delta", k, got)
			}
		}
	})

	t.Run("cumulative", func(t *testing.T) {
		sel := temporalitySelector("cumulative")
		// Should return the SDK default (cumulative for all kinds).
		for _, k := range kinds {
			if got := sel(k); got != metricdata.CumulativeTemporality {
				t.Errorf("temporalitySelector(\"cumulative\")(%v) = %v, want Cumulative", k, got)
			}
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		sel := temporalitySelector("Cumulative")
		if got := sel(sdkmetric.InstrumentKindHistogram); got != metricdata.CumulativeTemporality {
			t.Errorf("temporalitySelector(\"Cumulative\") should be case-insensitive, got %v", got)
		}
	})
}

func TestBuildSampler(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{"always_on", ""},
		{"always_off", ""},
		{"parentbased_traceidratio", "0.5"},
		{"parentbased_traceidratio", "invalid"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := buildSampler(tt.name, tt.arg)
			if s == nil {
				t.Error("sampler should not be nil")
			}
		})
	}
}

func TestActionMapping(t *testing.T) {
	tests := []struct {
		action        string
		wantLifecycle string
		wantActor     string
	}{
		{"install-detected", "install", "watcher"},
		{"install-rejected", "block", "watcher"},
		{"install-allowed", "allow", "watcher"},
		{"install-clean", "install", "watcher"},
		{"install-warning", "install", "watcher"},
		{"install-scan-error", "scan-error", "watcher"},
		{"block", "block", "user"},
		{"watcher-block", "block", "watcher"},
		{"allow", "allow", "user"},
		{"quarantine", "quarantine", "defenseclaw"},
		{"restore", "restore", "user"},
		{"deploy", "install", "user"},
		{"stop", "uninstall", "user"},
		{"disable", "disable", "defenseclaw"},
		{"enable", "enable", "user"},
		{"api-skill-disable", "disable", "user"},
		{"api-skill-enable", "enable", "user"},
		{"watch-start", "watch-start", "watcher"},
		{"watch-stop", "watch-stop", "watcher"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			m, ok := actionMap[tt.action]
			if !ok {
				t.Fatalf("action %q not in actionMap", tt.action)
			}
			if m.LifecycleAction != tt.wantLifecycle {
				t.Errorf("lifecycle: got %s, want %s", m.LifecycleAction, tt.wantLifecycle)
			}
			if m.Actor != tt.wantActor {
				t.Errorf("actor: got %s, want %s", m.Actor, tt.wantActor)
			}
		})
	}
}

func TestNonLifecycleActionsExcluded(t *testing.T) {
	nonLifecycle := []string{
		"sidecar-start", "sidecar-stop", "sidecar-connected",
		"gateway-tool-call", "gateway-tool-result",
		"gateway-approval-requested",
		"api-config-patch",
	}
	for _, action := range nonLifecycle {
		if _, ok := actionMap[action]; ok {
			t.Errorf("operational action %q should not be in lifecycle actionMap", action)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "ERROR", 17},
		{"ERROR", "ERROR", 17},
		{"HIGH", "WARN", 13},
		{"WARN", "WARN", 13},
		{"INFO", "INFO", 9},
		{"LOW", "INFO", 9},
		{"MEDIUM", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := severityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %s, want %s", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to…"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := truncateStr(tt.input, tt.max); got != tt.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

func TestBaseCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"curl http://example.com", "curl"},
		{"/usr/bin/bash -c echo hello", "bash"},
		{"", ""},
		{"  git status  ", "git"},
		{"npm", "npm"},
		{"/usr/local/bin/python3 script.py", "python3"},
		{"./relative/path/to/binary --flag", "binary"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := baseCommand(tt.input); got != tt.want {
				t.Errorf("baseCommand(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildScanBody_ExcludesSensitiveFields(t *testing.T) {
	result := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/path/to/project",
		Timestamp: time.Now(),
		Duration:  200 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "f1",
				Severity:    scanner.SeverityHigh,
				Title:       "Hardcoded secret",
				Description: "Found AWS key AKIA... in source",
				Location:    "/path/to/project/src/config.go:42",
				Remediation: "Use environment variables instead",
				Scanner:     "codeguard",
				Tags:        []string{"secrets", "aws"},
			},
		},
	}

	body := buildScanBody(result, "scan-001", "code")

	if len(body.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(body.Findings))
	}
	f := body.Findings[0]

	if f.ID != "f1" {
		t.Errorf("ID: got %q, want %q", f.ID, "f1")
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity: got %q, want %q", f.Severity, "HIGH")
	}
	if f.Title != "Hardcoded secret" {
		t.Errorf("Title: got %q, want %q", f.Title, "Hardcoded secret")
	}
	if f.Scanner != "codeguard" {
		t.Errorf("Scanner: got %q, want %q", f.Scanner, "codeguard")
	}
	if len(f.Tags) != 2 || f.Tags[0] != "secrets" {
		t.Errorf("Tags: got %v, want [secrets aws]", f.Tags)
	}

	bodyJSON, _ := json.Marshal(body)
	bodyStr := string(bodyJSON)
	for _, sensitive := range []string{"AKIA", "config.go:42", "environment variables"} {
		if containsStr(bodyStr, sensitive) {
			t.Errorf("scan body should not contain sensitive content %q", sensitive)
		}
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDeviceFingerprint_MissingFile(t *testing.T) {
	fp := deviceFingerprint("/nonexistent/path/to/key")
	if fp != "" {
		t.Errorf("expected empty fingerprint for missing file, got %q", fp)
	}
}

func TestDeviceFingerprint_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.key"
	if err := os.WriteFile(path, []byte("not a PEM file"), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for invalid PEM, got %q", fp)
	}
}

func TestDeviceFingerprint_WrongSeedSize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wrong.key"
	pemData := "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(pemData), 0600); err != nil {
		t.Fatal(err)
	}
	fp := deviceFingerprint(path)
	if fp != "" {
		t.Errorf("expected empty fingerprint for wrong seed size, got %q", fp)
	}
}

func TestDeviceFingerprint_ValidKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/device.key"

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: seed})
	if err := os.WriteFile(path, pemBlock, 0600); err != nil {
		t.Fatal(err)
	}

	fp := deviceFingerprint(path)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint for valid key")
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %s", len(fp), fp)
	}

	fp2 := deviceFingerprint(path)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %s != %s", fp, fp2)
	}
}

func TestScanSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "ERROR", 17},
		{"HIGH", "WARN", 13},
		{"MEDIUM", "INFO", 9},
		{"LOW", "INFO", 9},
		{"", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := scanSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestFindingSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "CRITICAL", 21},
		{"HIGH", "HIGH", 17},
		{"MEDIUM", "MEDIUM", 13},
		{"LOW", "LOW", 9},
		{"INFO", "INFO", 9},
		{"", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := findingSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestAlertSeverityToOTel(t *testing.T) {
	tests := []struct {
		input    string
		wantText string
		wantNum  int
	}{
		{"CRITICAL", "CRITICAL", 21},
		{"HIGH", "HIGH", 17},
		{"MEDIUM", "MEDIUM", 13},
		{"LOW", "LOW", 9},
		{"unknown", "LOW", 9},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			text, num := alertSeverityToOTel(tt.input)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

func TestResolveServiceName(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		attrs  map[string]string
		want   string
	}{
		{
			"env var takes priority",
			"from-env",
			map[string]string{"service.name": "from-config"},
			"from-env",
		},
		{
			"config attr used when no env",
			"",
			map[string]string{"service.name": "from-config"},
			"from-config",
		},
		{
			"default when both empty",
			"",
			map[string]string{},
			"defenseclaw",
		},
		{
			"default when nil attrs",
			"",
			nil,
			"defenseclaw",
		},
		{
			"env var empty string falls through",
			"",
			map[string]string{"service.name": ""},
			"defenseclaw",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OTEL_SERVICE_NAME", tt.envVal)
			got := resolveServiceName(tt.attrs)
			if got != tt.want {
				t.Errorf("resolveServiceName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildResource(t *testing.T) {
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"custom.attr": "custom-value",
	}
	res := buildResource(cfg, "1.0.0-test")
	if res == nil {
		t.Fatal("resource should not be nil")
	}
}

func TestBuildResource_ServiceNameFromEnv(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "my-app-from-env")
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"service.name": "from-config",
	}

	res := buildResource(cfg, "1.0.0")
	iter := res.Iter()
	var found string
	count := 0
	for iter.Next() {
		kv := iter.Attribute()
		if string(kv.Key) == "service.name" {
			found = kv.Value.AsString()
			count++
		}
	}
	if found != "my-app-from-env" {
		t.Errorf("service.name = %q, want %q", found, "my-app-from-env")
	}
	if count != 1 {
		t.Errorf("service.name appeared %d times, want exactly 1 (no duplicates)", count)
	}
}

func TestBuildResource_ServiceNameDedup(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{
		"service.name": "custom-name",
		"custom.attr":  "value",
	}

	res := buildResource(cfg, "1.0.0")
	iter := res.Iter()
	serviceNameCount := 0
	customAttrFound := false
	var serviceNameVal string
	for iter.Next() {
		kv := iter.Attribute()
		switch string(kv.Key) {
		case "service.name":
			serviceNameCount++
			serviceNameVal = kv.Value.AsString()
		case "custom.attr":
			customAttrFound = true
		}
	}
	if serviceNameCount != 1 {
		t.Errorf("service.name appeared %d times, want 1", serviceNameCount)
	}
	if serviceNameVal != "custom-name" {
		t.Errorf("service.name = %q, want %q", serviceNameVal, "custom-name")
	}
	if !customAttrFound {
		t.Error("custom.attr should still be present in resource")
	}
}

func TestBuildResource_DefaultServiceName(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	cfg := disabledCfg()
	cfg.OTel.Resource.Attributes = map[string]string{}

	res := buildResource(cfg, "1.0.0")
	iter := res.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		if string(kv.Key) == "service.name" {
			if kv.Value.AsString() != "defenseclaw" {
				t.Errorf("service.name = %q, want %q", kv.Value.AsString(), "defenseclaw")
			}
			return
		}
	}
	t.Error("service.name attribute not found")
}

func TestBuildResource_AgentWatchContextAttributes(t *testing.T) {
	cfg := disabledCfg()
	cfg.TenantID = "tenant-a"
	cfg.WorkspaceID = "workspace-1"
	cfg.DeploymentMode = "standalone"
	cfg.DiscoverySource = "registry"

	res := buildResource(cfg, "1.0.0")
	got := map[string]string{}
	iter := res.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		got[string(kv.Key)] = kv.Value.AsString()
	}

	for key, want := range map[string]string{
		"defenseclaw.tenant.id":        "tenant-a",
		"defenseclaw.workspace.id":     "workspace-1",
		"deployment.environment":       "test",
		"defenseclaw.deployment.mode":  "standalone",
		"defenseclaw.discovery.source": "registry",
	} {
		if got[key] != want {
			t.Errorf("%s=%q, want %q", key, got[key], want)
		}
	}
}

// ---------------------------------------------------------------------------
// OTel metric verification tests — ensure guardrail metrics are actually
// recorded with the correct instruments and attribute values.
// ---------------------------------------------------------------------------

func TestRecordGuardrailEvaluation_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordGuardrailEvaluation(ctx, "guardrail-proxy", "block")
	p.RecordGuardrailEvaluation(ctx, "guardrail-proxy", "allow")
	p.RecordGuardrailEvaluation(ctx, "guardrail-proxy", "block")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.guardrail.evaluations")
	if found == nil {
		t.Fatal("metric defenseclaw.guardrail.evaluations not found")
		return
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	blockCount := counterValueByAttr(sum, "guardrail.action_taken", "block")
	allowCount := counterValueByAttr(sum, "guardrail.action_taken", "allow")

	if blockCount != 2 {
		t.Errorf("block count = %d, want 2", blockCount)
	}
	if allowCount != 1 {
		t.Errorf("allow count = %d, want 1", allowCount)
	}
}

func TestRecordGuardrailLatency_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordGuardrailLatency(ctx, "guardrail-proxy", 15.5)
	p.RecordGuardrailLatency(ctx, "guardrail-proxy", 22.0)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "defenseclaw.guardrail.latency")
	if found == nil {
		t.Fatal("metric defenseclaw.guardrail.latency not found")
		return
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	if len(hist.DataPoints) == 0 {
		t.Fatal("expected at least one histogram data point")
	}

	dp := hist.DataPoints[0]
	if dp.Count != 2 {
		t.Errorf("histogram count = %d, want 2", dp.Count)
	}
	if dp.Sum != 37.5 {
		t.Errorf("histogram sum = %f, want 37.5", dp.Sum)
	}

	hasScanner := hasAttribute(dp.Attributes, "guardrail.scanner", "guardrail-proxy")
	if !hasScanner {
		t.Error("histogram missing attribute guardrail.scanner=guardrail-proxy")
	}
}

func TestRecordLLMTokens_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordLLMTokens(ctx, "chat", "openai", "gpt-4", "test-agent", "agent-id-1", 150, 75)
	p.RecordLLMTokens(ctx, "chat", "openai", "gpt-4", "test-agent", "agent-id-1", 200, 0) // no completion tokens

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "gen_ai.client.token.usage")
	if found == nil {
		t.Fatal("metric gen_ai.client.token.usage not found")
		return
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	var inputSum, outputSum float64
	for _, dp := range hist.DataPoints {
		for _, attr := range dp.Attributes.ToSlice() {
			if string(attr.Key) == "gen_ai.token.type" {
				if attr.Value.AsString() == "input" {
					inputSum += dp.Sum
				} else if attr.Value.AsString() == "output" {
					outputSum += dp.Sum
				}
			}
		}
	}

	if inputSum != 350 {
		t.Errorf("input token sum = %v, want 350", inputSum)
	}
	if outputSum != 75 {
		t.Errorf("output token sum = %v, want 75", outputSum)
	}

	// Verify gen_ai.agent.name attribute is present on data points.
	for _, dp := range hist.DataPoints {
		hasAgentName := hasAttribute(dp.Attributes, "gen_ai.agent.name", "test-agent")
		if !hasAgentName {
			t.Error("histogram data point missing attribute gen_ai.agent.name=test-agent")
		}
		// v7 cardinality-safe identity: gen_ai.agent.id is bounded
		// per deployment (one per configured agent) and gives o11y a
		// stable join key that survives renames. Pin its presence so
		// a regression in EndLLMSpan threading doesn't silently drop it.
		hasAgentID := hasAttribute(dp.Attributes, "gen_ai.agent.id", "agent-id-1")
		if !hasAgentID {
			t.Error("histogram data point missing attribute gen_ai.agent.id=agent-id-1")
		}
	}
}

func TestRecordGuardrailEvaluation_DisabledProvider_NoOp(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.RecordGuardrailEvaluation(context.Background(), "test", "block")
}

func TestDisabledProvider_RecordPolicyEvaluation_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx := context.Background()
	p.RecordPolicyEvaluation(ctx, "admission", "blocked")
	p.RecordPolicyLatency(ctx, "firewall", 42.0)
	p.RecordPolicyReload(ctx, "success")
}

func TestDisabledProvider_EmitPolicyDecision_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	p.EmitPolicyDecision("admission", "blocked", "evil-skill", "skill", "on block list", nil)
}

func TestEmitPolicyDecision_EnabledProvider_AllVerdicts(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	p.EmitPolicyDecision("admission", "blocked", "evil-skill", "skill", "on block list", nil)
	p.EmitPolicyDecision("firewall", "deny", "evil.com", "network", "denied by rule", map[string]string{
		"rule_name": "block-external",
	})
	p.EmitPolicyDecision("reload", "success", "/etc/policies", "", "OPA reload", nil)
	p.EmitPolicyDecision("admission", "failed", "broken", "skill", "engine error", map[string]string{
		"error": "timeout",
		"empty": "",
	})
	p.EmitPolicyDecision("sandbox", "allow", "good-skill", "skill", "clean", nil)
}

func TestDisabledProvider_PolicySpan_NoPanic(t *testing.T) {
	p, _ := NewProvider(context.Background(), disabledCfg(), "test")
	ctx, span := p.StartPolicySpan(context.Background(), "firewall", "network", "example.com")
	if span != nil {
		t.Error("span should be nil when disabled")
	}
	if ctx == nil {
		t.Error("context should not be nil")
	}
	p.EndPolicySpan(nil, "firewall", "allow", "default allow", time.Now().Add(-10*time.Millisecond))
}

func TestRecordPolicyEvaluation_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordPolicyEvaluation(ctx, "admission", "blocked")
	p.RecordPolicyEvaluation(ctx, "admission", "clean")
	p.RecordPolicyEvaluation(ctx, "firewall", "deny")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.policy.evaluations")
	if found == nil {
		t.Fatal("metric defenseclaw.policy.evaluations not found")
		return
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	blockedCount := counterValueByAttr(sum, "policy.verdict", "blocked")
	if blockedCount != 1 {
		t.Errorf("blocked count = %d, want 1", blockedCount)
	}

	cleanCount := counterValueByAttr(sum, "policy.verdict", "clean")
	if cleanCount != 1 {
		t.Errorf("clean count = %d, want 1", cleanCount)
	}

	denyCount := counterValueByAttr(sum, "policy.verdict", "deny")
	if denyCount != 1 {
		t.Errorf("deny count = %d, want 1", denyCount)
	}
}

func TestRecordPolicyLatency_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordPolicyLatency(ctx, "admission", 5.0)
	p.RecordPolicyLatency(ctx, "admission", 12.5)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findHistogram(rm, "defenseclaw.policy.latency")
	if found == nil {
		t.Fatal("metric defenseclaw.policy.latency not found")
		return
	}

	hist, ok := found.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", found.Data)
	}

	if len(hist.DataPoints) == 0 {
		t.Fatal("expected at least one histogram data point")
	}

	dp := hist.DataPoints[0]
	if dp.Count != 2 {
		t.Errorf("histogram count = %d, want 2", dp.Count)
	}
	if dp.Sum != 17.5 {
		t.Errorf("histogram sum = %f, want 17.5", dp.Sum)
	}
}

func TestRecordPolicyReload_EmitsMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	p.RecordPolicyReload(ctx, "success")
	p.RecordPolicyReload(ctx, "failed")
	p.RecordPolicyReload(ctx, "success")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := findCounter(rm, "defenseclaw.policy.reloads")
	if found == nil {
		t.Fatal("metric defenseclaw.policy.reloads not found")
		return
	}

	sum, ok := found.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected Sum[int64], got %T", found.Data)
	}

	successCount := counterValueByAttr(sum, "policy.status", "success")
	failedCount := counterValueByAttr(sum, "policy.status", "failed")

	if successCount != 2 {
		t.Errorf("success count = %d, want 2", successCount)
	}
	if failedCount != 1 {
		t.Errorf("failed count = %d, want 1", failedCount)
	}
}

func TestStartEndPolicySpan_RecordsAttributes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	ctx := context.Background()
	start := time.Now()
	ctx, span := p.StartPolicySpan(ctx, "firewall", "network", "evil.example.com")
	if span == nil {
		t.Fatal("span should not be nil with trace-enabled provider")
	}
	if ctx == nil {
		t.Fatal("context should not be nil")
	}

	time.Sleep(time.Millisecond)
	p.EndPolicySpan(span, "firewall", "deny", "blocked by firewall rule", start)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one recorded span")
	}

	s := spans[len(spans)-1]
	if s.Name != "policy/firewall" {
		t.Errorf("span name = %q, want %q", s.Name, "policy/firewall")
	}

	attrMap := make(map[string]string)
	for _, a := range s.Attributes {
		attrMap[string(a.Key)] = a.Value.AsString()
	}
	if attrMap["defenseclaw.policy.domain"] != "firewall" {
		t.Errorf("domain attr = %q, want %q", attrMap["defenseclaw.policy.domain"], "firewall")
	}
	if attrMap["defenseclaw.policy.target_type"] != "network" {
		t.Errorf("target_type attr = %q, want %q", attrMap["defenseclaw.policy.target_type"], "network")
	}
	if attrMap["defenseclaw.policy.target_name"] != "evil.example.com" {
		t.Errorf("target_name attr = %q, want %q", attrMap["defenseclaw.policy.target_name"], "evil.example.com")
	}
	if attrMap["defenseclaw.policy.verdict"] != "deny" {
		t.Errorf("verdict attr = %q, want %q", attrMap["defenseclaw.policy.verdict"], "deny")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	evalMetric := findCounter(rm, "defenseclaw.policy.evaluations")
	if evalMetric == nil {
		t.Fatal("EndPolicySpan should also record policy.evaluations metric")
		return
	}
}

func TestStartEndPolicySpan_BlockedSetsErrorStatus(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	start := time.Now()
	_, span := p.StartPolicySpan(context.Background(), "admission", "skill", "evil-skill")
	p.EndPolicySpan(span, "admission", "blocked", "on block list", start)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected recorded span")
	}
	s := spans[len(spans)-1]
	if s.Status.Code.String() != "Error" {
		t.Errorf("span status = %q, want Error for blocked verdict", s.Status.Code.String())
	}
}

func TestStartEndPolicySpan_AllowSetsOkStatus(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	p, err := NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	start := time.Now()
	_, span := p.StartPolicySpan(context.Background(), "admission", "skill", "safe-skill")
	p.EndPolicySpan(span, "admission", "allow", "clean scan", start)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected recorded span")
	}
	s := spans[len(spans)-1]
	if s.Status.Code.String() != "Ok" {
		t.Errorf("span status = %q, want Ok for allow verdict", s.Status.Code.String())
	}
}

func TestEndPolicySpan_NilSpan_StillRecordsMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer p.Shutdown(context.Background())

	p.EndPolicySpan(nil, "sandbox", "restrict", "denied endpoints", time.Now().Add(-5*time.Millisecond))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	evalMetric := findCounter(rm, "defenseclaw.policy.evaluations")
	if evalMetric == nil {
		t.Fatal("EndPolicySpan(nil) should still record policy.evaluations metric")
		return
	}
}

func TestNilProvider_PolicyMethods_NoPanic(t *testing.T) {
	var p *Provider
	ctx := context.Background()

	p.RecordPolicyEvaluation(ctx, "admission", "blocked")
	p.RecordPolicyLatency(ctx, "firewall", 10.0)
	p.RecordPolicyReload(ctx, "success")
	p.EmitPolicyDecision("admission", "blocked", "target", "skill", "reason", nil)

	ctx2, span := p.StartPolicySpan(ctx, "firewall", "network", "example.com")
	if span != nil {
		t.Error("nil provider should return nil span")
	}
	if ctx2 == nil {
		t.Error("nil provider should still return non-nil context")
	}
	p.EndPolicySpan(nil, "firewall", "deny", "reason", time.Now())
}

func TestPolicyVerdictSeverity(t *testing.T) {
	tests := []struct {
		verdict  string
		wantText string
		wantNum  int
	}{
		{"blocked", "WARN", 13},
		{"rejected", "WARN", 13},
		{"deny", "WARN", 13},
		{"block", "WARN", 13},
		{"failed", "ERROR", 17},
		{"allow", "INFO", 9},
		{"clean", "INFO", 9},
		{"success", "INFO", 9},
	}
	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			text, num := policyVerdictSeverity(tt.verdict)
			if text != tt.wantText {
				t.Errorf("text: got %q, want %q", text, tt.wantText)
			}
			if num != tt.wantNum {
				t.Errorf("num: got %d, want %d", num, tt.wantNum)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Metric collection helpers
// ---------------------------------------------------------------------------

func findCounter(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func findHistogram(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	return findCounter(rm, name) // same lookup, different data type
}

func counterValueByAttr(sum metricdata.Sum[int64], key, val string) int64 {
	for _, dp := range sum.DataPoints {
		if hasAttribute(dp.Attributes, key, val) {
			return dp.Value
		}
	}
	return 0
}

func hasAttribute(attrs attribute.Set, key, val string) bool {
	v, ok := attrs.Value(attribute.Key(key))
	return ok && v.AsString() == val
}
