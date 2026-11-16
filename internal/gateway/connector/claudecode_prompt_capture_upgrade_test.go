// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeManagedCleanupKeepsRecordedOperatorPromptCapture(t *testing.T) {
	for _, recorded := range []string{"0", "1", "absent"} {
		t.Run(recorded, func(t *testing.T) {
			dir := t.TempDir()
			pinClaudeUpgradeTestOwner(t, dir)
			settingsPath := filepath.Join(dir, "settings.json")
			useClaudeSettings(t, settingsPath)
			productToken := strings.Repeat("b", 64)
			writeClaudeUpgradeSettings(t, settingsPath, map[string]interface{}{"env": map[string]string{
				"CLAUDE_CODE_ENABLE_TELEMETRY":        "1",
				"OTEL_LOGS_EXPORTER":                  "otlp",
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    "https://collector.example.test/v1/logs",
				"OTEL_LOG_USER_PROMPTS":               "1",
				"OTEL_METRICS_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:19081/otlp/claudecode/" + productToken + "/v1/metrics",
				"OTEL_EXPORTER_OTLP_METRICS_HEADERS":  "authorization=Bearer " + productToken + ",x-defenseclaw-source=claudecode",
			}})
			managed := map[string]string{
				"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:19081/otlp/claudecode/" + productToken + "/v1/metrics",
				"OTEL_EXPORTER_OTLP_METRICS_HEADERS":  "authorization=Bearer " + productToken + ",x-defenseclaw-source=claudecode",
			}
			if recorded != "absent" {
				managed["OTEL_LOG_USER_PROMPTS"] = recorded
			}
			if err := NewClaudeCodeConnector().saveBackup(dir, claudeCodeBackup{ManagedEnv: managed}); err != nil {
				t.Fatal(err)
			}
			if _, err := RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
				t.Fatal(err)
			}
			got := readClaudeUpgradeEnv(t, settingsPath)
			if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != "https://collector.example.test/v1/logs" ||
				got["OTEL_LOGS_EXPORTER"] != "otlp" || got["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
				t.Fatal("operator logs route changed")
			}
			if got["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"] != "" {
				t.Fatal("product metrics route remains")
			}
			want := ""
			if recorded == "0" {
				want = "1"
			}
			if got["OTEL_LOG_USER_PROMPTS"] != want {
				t.Fatalf("prompt capture = %q, want %q with recorded product value %q", got["OTEL_LOG_USER_PROMPTS"], want, recorded)
			}
		})
	}
}
