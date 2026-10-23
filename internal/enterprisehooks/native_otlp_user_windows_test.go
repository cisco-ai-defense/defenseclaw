// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// GAP-0836: on the managed Windows host std1's Codex and Claude Code configs
// kept the exporters of an earlier per-user install on 127.0.0.1:19010 while
// the managed gateway served 18970. Verify must report that row so the
// guardian repairs it, and install must remove the exporters and their
// credentials from the account's profile.
func TestWindowsManagedRowRefusesAndRemovesStalePerUserNativeOTLP(t *testing.T) {
	previous := windowsEnterpriseTargetImpersonation
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		return errors.New("read-only verification attempted target impersonation")
	}
	t.Cleanup(func() { windowsEnterpriseTargetImpersonation = previous })
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	bearer := strings.Repeat("e7", 32)
	codex := "model = \"gpt-5\"\r\n[otel]\r\nlog_user_prompt = true\r\n"
	for _, pair := range [][2]string{{"exporter", "logs"}, {"metrics_exporter", "metrics"}, {"trace_exporter", "traces"}} {
		codex += "[otel." + pair[0] + ".otlp-http]\r\nendpoint = 'http://127.0.0.1:19010/v1/" + pair[1] + "'\r\nprotocol = 'json'\r\n" +
			"[otel." + pair[0] + ".otlp-http.headers]\r\nauthorization = 'Bearer " + bearer + "'\r\n" +
			"x-defenseclaw-source = 'codex'\r\nx-defenseclaw-client = 'codex-otel/1.0'\r\n"
	}
	headers := "authorization=Bearer " + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	claude := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp","OTEL_METRICS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `",` +
		`"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:19010/v1/logs","OTEL_EXPORTER_OTLP_LOGS_HEADERS":"` + headers + `"}}`
	files := map[string]string{
		filepath.Join(home, ".codex", "config.toml"):    codex,
		filepath.Join(home, ".claude", "settings.json"): claude,
		// The per-user install also left its ordinary connector lock files.
		filepath.Join(home, ".codex", "config.toml.lock"):    "",
		filepath.Join(home, ".claude", "settings.json.lock"): "",
	}
	for _, scope := range []connector.OTLPPathTokenScope{connector.OTLPScopeCodex, connector.OTLPScopeClaude} {
		path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
		if err != nil {
			t.Fatal(err)
		}
		files[path] = bearer
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{"codex", "claudecode"} {
		err := windowsManagedUserNativeOTLPAbsent(name, home, dataDir, sid)
		if err == nil || !strings.Contains(err.Error(), "native OTLP exporter") {
			t.Fatalf("%s: verify accepted a stale per-user exporter: %v", name, err)
		}
		if strings.Contains(err.Error(), bearer) || strings.Contains(err.Error(), "19010") {
			t.Fatalf("%s: verify error carries a value: %v", name, err)
		}
		if err := connector.WithUserHomeDir(home, func() error {
			return removeWindowsManagedUserNativeOTLPAsTarget(name, dataDir)
		}); err != nil {
			t.Fatalf("%s: remove: %v", name, err)
		}
		if err := windowsManagedUserNativeOTLPAbsent(name, home, dataDir, sid); err != nil {
			t.Fatalf("%s: verify after repair: %v", name, err)
		}
	}
	for path := range files {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(path, ".token") {
			t.Fatalf("stale native OTLP credential remains: %s", filepath.Base(path))
		}
		if strings.Contains(string(data), "19010") || strings.Contains(string(data), bearer) {
			t.Fatalf("%s keeps the stale exporter:\n%s", filepath.Base(path), data)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml")); !strings.Contains(string(data), "model = \"gpt-5\"") {
		t.Fatalf("unrelated Codex setting changed:\n%s", data)
	}
}

// The same row through the real Claude Code managed Install and Verify.
func TestWindowsClaudeManagedVerifyAndRepairStalePerUserNativeOTLP(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(fixture.home, ".claude", "settings.json")
	if connector.ClaudeCodeSettingsPathOverride != "" {
		settingsPath = connector.ClaudeCodeSettingsPathOverride
	}
	bearer := strings.Repeat("f3", 32)
	headers := "authorization=Bearer " + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	stale := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `"},"model":"opus"}`
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "native OTLP exporter") {
		t.Fatalf("Verify accepted a stale per-user exporter: %v", err)
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("repair: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "19010") || strings.Contains(string(data), bearer) || !strings.Contains(string(data), "opus") {
		t.Fatalf("repair left the stale exporter or lost a setting:\n%s", data)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify after repair: %v", err)
	}
}
