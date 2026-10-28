// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-1389 end to end in the install watcher: the benign skill-only
// formatting plugin with only judge HIGHs (the native G51 finding set) installs with a HIGH warning and an
// audit row in default; a static concrete threat beside the same judge
// findings, or an explicit HIGH quarantine, is still rejected and quarantined.
func TestJudgeOnlyPluginHighWarnsInDefault(t *testing.T) {
	judge := []scanner.Finding{
		{ID: "p1", RuleID: "LLM-OB-009-001", Severity: scanner.SeverityHigh, Title: "Manifest-only plugin with no source code available", Location: "plugin:r104fx-ok"},
		{ID: "p2", RuleID: "META-LLM-001", Severity: scanner.SeverityHigh, Title: "Manifest-only plugin with opaque functionality"},
		{ID: "p3", RuleID: "META-LLM-002", Severity: scanner.SeverityMedium, Title: "Unable to validate permission claims"},
		{ID: "p4", RuleID: "SCAN-LLM-NO-SOURCE", Severity: scanner.SeverityMedium, Title: "LLM analysis ran without any plugin source files"},
		{ID: "p5", RuleID: "PERM-NONE", Severity: scanner.SeverityLow, Title: "declares no permissions"},
	}
	static := scanner.Finding{ID: "p6", RuleID: "SRC-EXFIL-001", Severity: scanner.SeverityHigh, Title: "reads ~/.ssh/id_rsa and uploads it"}
	for _, tc := range []struct {
		name     string
		findings []scanner.Finding
		high     *config.AdmissionAction
		want     Verdict
	}{
		{name: "judge-only HIGH", findings: judge, want: VerdictWarning},
		{name: "static HIGH beside the judge", findings: append(append([]scanner.Finding(nil), judge...), static), want: VerdictRejected},
		{name: "explicit HIGH quarantine", findings: judge, high: &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}, want: VerdictRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, skillDir := setupTestEnv(t)
			cfg.Gateway.Watcher.Plugin.TakeAction = true
			cfg.Admission.Plugin.Actions.High = tc.high
			rows := auditRows(t, logger)
			pluginDir := t.TempDir()
			plugin := filepath.Join(pluginDir, "r104fx-ok")
			skill := filepath.Join(plugin, "skills", "helper", "SKILL.md")
			if err := os.MkdirAll(filepath.Dir(skill), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(plugin, ".claude-plugin"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(plugin, ".claude-plugin", "plugin.json"), []byte(`{"name":"r104fx-ok","version":"1.0.0"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(skill, []byte("---\nname: helper\n---\nFormat status notes as a short bulleted list.\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)
			w.scannerFactory = func(InstallEvent) scanner.Scanner {
				return &countingScanner{name: "plugin-scanner", findings: tc.findings}
			}
			res := w.runAdmission(context.Background(), InstallEvent{Type: InstallPlugin, Name: "r104fx-ok", Path: plugin, Connector: "claudecode", Timestamp: time.Now()})
			if res.Verdict != tc.want || res.MaxSeverity != "HIGH" {
				t.Fatalf("verdict %q max %q (%s), want %q with HIGH kept", res.Verdict, res.MaxSeverity, res.Reason, tc.want)
			}
			_, statErr := os.Stat(skill)
			got := strings.Join(rows(), "\n")
			if tc.want == VerdictWarning {
				if statErr != nil || !strings.Contains(got, "install-warning") || !strings.Contains(got, "severity=HIGH") {
					t.Fatalf("files %v, audit %s: want the plugin in place and a HIGH install-warning row", statErr, got)
				}
				return
			}
			if !os.IsNotExist(statErr) || !strings.Contains(got, "install-rejected") {
				t.Fatalf("files %v, audit %s: want the plugin quarantined and an install-rejected row", statErr, got)
			}
		})
	}
}
