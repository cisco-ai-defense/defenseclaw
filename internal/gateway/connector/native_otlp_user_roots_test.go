// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0928/0929: the managed Windows check reads each agent configuration
// itself (relocated roots, links) and hands the bytes over; a configuration
// anywhere is cleaned by path. Both judge exactly as the default-path check
// does, and the credential goes only when the caller says every configuration
// is clean.
func TestUserNativeOTLPChecksAConfigurationByBytesAndByPath(t *testing.T) {
	bearer := strings.Repeat("d2", 32)
	codex := "model = \"gpt-5\"\n[otel]\nlog_user_prompt = true\n" +
		"[otel.exporter.otlp-http]\nendpoint = 'http://127.0.0.1:19010/v1/logs'\nprotocol = 'json'\n" +
		"[otel.exporter.otlp-http.headers]\nauthorization = 'Bearer " + bearer + "'\n" +
		"x-defenseclaw-source = 'codex'\nx-defenseclaw-client = 'codex-otel/1.0'\n"
	headers := "authorization=Bearer " + bearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	claude := `{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_LOGS_EXPORTER":"otlp",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `"},"model":"opus"}`
	for _, tc := range []struct {
		name, file, body string
		scope            OTLPPathTokenScope
	}{
		{"codex", "config.toml", codex, OTLPScopeCodex},
		{"claudecode", "settings.json", claude, OTLPScopeClaude},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			relocated := filepath.Join(t.TempDir(), "agent-root", tc.file)
			if err := os.MkdirAll(filepath.Dir(relocated), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(relocated, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			token, err := OTLPPathTokenFilePath(dataDir, tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(bearer), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
			names, err := UserNativeOTLPResidueIn(tc.name, []byte(tc.body), nil, opts)
			if err != nil || len(names) == 0 {
				t.Fatalf("residue by bytes = %v, %v", names, err)
			}
			for _, name := range names {
				if strings.Contains(name, bearer) || strings.Contains(name, "19010") || !strings.HasPrefix(name, tc.file+" ") {
					t.Fatalf("residue name %q carries a value or misses its file", name)
				}
			}
			removed, err := RemoveUserNativeOTLPAt(tc.name, relocated, opts)
			if err != nil || strings.Join(removed, ",") != strings.Join(names, ",") {
				t.Fatalf("removal at the relocated path = %v, %v; want %v", removed, err, names)
			}
			data, err := os.ReadFile(relocated)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), bearer) || strings.Contains(string(data), "19010") {
				t.Fatalf("the relocated configuration keeps the exporter:\n%s", data)
			}
			if again, err := UserNativeOTLPResidueIn(tc.name, data, nil, opts); err != nil || len(again) != 0 {
				t.Fatalf("residue after removal = %v, %v", again, err)
			}
			if _, err := os.Stat(token); err != nil {
				t.Fatal("removing one configuration revoked the credential")
			}
			if left, err := UserNativeOTLPCredentialResidue(tc.name, opts); err != nil || len(left) != 1 {
				t.Fatalf("credential residue = %v, %v", left, err)
			}
			if _, err := RevokeUserNativeOTLPCredential(tc.name, opts); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(token); !os.IsNotExist(err) {
				t.Fatalf("credential still present: %v", err)
			}
		})
	}
}

// The location a per-user setup recorded is read only from a record of that
// connector and file, with an absolute target.
func TestUserAgentConfigRecordTargetNeedsTheConnectorsOwnRecord(t *testing.T) {
	target := filepath.Join(t.TempDir(), "codex-home", "config.toml")
	record := func(connector, logical, path string) []byte {
		data, err := json.Marshal(map[string]any{"version": managedBackupVersion, "connector": connector, "logical_name": logical, "path": path})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if got := UserAgentConfigRecordTarget("codex", record("codex", "config.toml", target)); got != filepath.Clean(target) {
		t.Fatalf("recorded target = %q, want %q", got, target)
	}
	for _, bad := range [][]byte{
		record("claudecode", "config.toml", target),
		record("codex", "hooks.json", target),
		record("codex", "config.toml", "relative/config.toml"),
		record("codex", "config.toml", filepath.Join(filepath.Dir(target), "other.toml")),
		[]byte("{"),
	} {
		if got := UserAgentConfigRecordTarget("codex", bad); got != "" {
			t.Fatalf("record %s named %q", bad, got)
		}
	}
	if !strings.HasSuffix(UserAgentConfigRecordPath("/data", "claudecode"), filepath.Join("connector_backups", "claudecode", "settings.json.json")) {
		t.Fatalf("Claude Code record path = %s", UserAgentConfigRecordPath("/data", "claudecode"))
	}
}
