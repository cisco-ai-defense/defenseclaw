// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The bearer of a pre-1.0.4 per-user render that no file of the install
// records any more (GAP-0836, dc-fc-r104-sa-ewin1 dcw-std1).
const markedOrphanBearer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func markedOrphanCodexConfig(port, source, host string) []byte {
	var b strings.Builder
	b.WriteString("model = \"gpt-5\"\n\n[otel]\nenvironment = 'windows'\nlog_user_prompt = true\n\n")
	for _, signal := range []struct{ key, path string }{{"exporter", "logs"}, {"metrics_exporter", "metrics"}, {"trace_exporter", "traces"}} {
		b.WriteString("[otel." + signal.key + ".otlp-http]\nendpoint = 'http://" + host + ":" + port + "/v1/" + signal.path + "'\nprotocol = 'json'\n\n")
		b.WriteString("[otel." + signal.key + ".otlp-http.headers]\nauthorization = 'Bearer " + markedOrphanBearer + "'\nx-defenseclaw-client = 'codex-otel/1.0'\n")
		if source != "" {
			b.WriteString("x-defenseclaw-source = '" + source + "'\n")
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func markedOrphanClaudeSettings(port string) []byte {
	headers := "authorization=Bearer " + markedOrphanBearer + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
	return []byte(`{"model":"opus","env":{"AWS_REGION":"us-east-1","CLAUDE_CODE_ENABLE_TELEMETRY":"1",` +
		`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:` + port + `","OTEL_EXPORTER_OTLP_HEADERS":"` + headers + `",` +
		`"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:` + port + `/v1/logs","OTEL_EXPORTER_OTLP_LOGS_HEADERS":"` + headers + `",` +
		`"OTEL_EXPORTER_OTLP_PROTOCOL":"http/json","OTEL_LOGS_EXPORTER":"otlp","OTEL_METRICS_EXPORTER":"otlp","OTEL_SERVICE_NAME":"claudecode"}}`)
}

func markedOrphanOpts(t *testing.T, managed bool) SetupOpts {
	return SetupOpts{DataDir: t.TempDir(), ManagedEnterprise: true, ManagedMarkedOrphanExporters: managed,
		ManagedServedAddrs: []string{"127.0.0.1:18970", "127.0.0.1:4000"}}
}

func TestManagedWindowsTakeBackRemovesAMarkedCodexExporterOnAnUnservedLoopbackPort(t *testing.T) {
	config := markedOrphanCodexConfig("19010", "codex", "127.0.0.1")
	opts := markedOrphanOpts(t, true)
	out, removed, err := UserNativeOTLPWithout("codex", config, nil, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	// log_user_prompt goes with them: the earlier render wrote it beside
	// the exporters (restoreCodexOtelEntries, as for a recorded credential).
	for _, want := range []string{"config.toml otel.exporter", "config.toml otel.metrics_exporter", "config.toml otel.trace_exporter"} {
		if !slices.Contains(removed, want) {
			t.Fatalf("removed = %v, want %s among them", removed, want)
		}
	}
	if strings.Contains(string(out), "19010") || strings.Contains(string(out), markedOrphanBearer) {
		t.Fatalf("the exporter or its bearer stayed:\n%s", out)
	}
	if !strings.Contains(string(out), `model = "gpt-5"`) {
		t.Fatalf("the account's own key was lost:\n%s", out)
	}
	if !UserNativeOTLPMarkedOrphanIn("codex", config, opts) {
		t.Fatal("UserNativeOTLPMarkedOrphanIn = false, want true (the take-back keeps a copy)")
	}
	if kept := UserNativeOTLPMarkedKeptIn("codex", config, nil, opts); len(kept) != 0 {
		t.Fatalf("UserNativeOTLPMarkedKeptIn = %v, want none (it is removed)", kept)
	}
}

func TestManagedWindowsTakeBackRemovesAMarkedClaudeCodeExporterOnAnUnservedLoopbackPort(t *testing.T) {
	settings := markedOrphanClaudeSettings("19010")
	opts := markedOrphanOpts(t, true)
	out, removed, err := UserNativeOTLPWithout("claudecode", settings, nil, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 || strings.Contains(string(out), markedOrphanBearer) || strings.Contains(string(out), "19010") {
		t.Fatalf("removed = %v, out:\n%s", removed, out)
	}
	if !strings.Contains(string(out), `"AWS_REGION"`) || !strings.Contains(string(out), `"model"`) {
		t.Fatalf("the account's own settings were lost:\n%s", out)
	}
}

func TestMarkedExporterKeepsTheOwnershipRuleOutsideTheManagedOrphanShape(t *testing.T) {
	cases := []struct {
		name, connector string
		config          []byte
		managed         bool
		wantKept        bool
	}{
		{"host setup (not the managed profile)", "codex", markedOrphanCodexConfig("19010", "codex", "127.0.0.1"), false, true},
		{"a port the managed gateway serves", "codex", markedOrphanCodexConfig("18970", "codex", "127.0.0.1"), true, true},
		{"only one marker", "codex", markedOrphanCodexConfig("19010", "", "127.0.0.1"), true, true},
		{"another connector's source", "codex", markedOrphanCodexConfig("19010", "claudecode", "127.0.0.1"), true, true},
		{"a non-loopback collector", "codex", markedOrphanCodexConfig("19010", "codex", "collector.example.com"), true, true},
		{"claude host setup", "claudecode", markedOrphanClaudeSettings("19010"), false, true},
		{"claude served port", "claudecode", markedOrphanClaudeSettings("4000"), true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := markedOrphanOpts(t, tc.managed)
			removed, err := UserNativeOTLPResidueIn(tc.connector, tc.config, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(removed) != 0 {
				t.Fatalf("removed %v: an exporter nothing proves is DefenseClaw's must stay (GAP-1511)", removed)
			}
			if UserNativeOTLPMarkedOrphanIn(tc.connector, tc.config, opts) {
				t.Fatal("UserNativeOTLPMarkedOrphanIn = true outside the managed orphan shape")
			}
			if kept := UserNativeOTLPMarkedKeptIn(tc.connector, tc.config, nil, opts); (len(kept) > 0) != tc.wantKept {
				t.Fatalf("UserNativeOTLPMarkedKeptIn = %v, want it named for the warning", kept)
			}
		})
	}
}

func TestNativeOTLPMarkedOrphanRemovedNoteLastsWhileItsCopyIsThere(t *testing.T) {
	dataDir := t.TempDir()
	if NativeOTLPMarkedOrphanRemoved(dataDir, "codex") {
		t.Fatal("note reported with no note")
	}
	copyPath := filepath.Join(t.TempDir(), "config.toml"+NativeOTLPMarkedOrphanBackupSuffix)
	if err := os.WriteFile(copyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecordNativeOTLPMarkedOrphanRemoved(dataDir, "codex", copyPath); err != nil {
		t.Fatal(err)
	}
	if !NativeOTLPMarkedOrphanRemoved(dataDir, "codex") {
		t.Fatal("note not reported while its copy is there")
	}
	if code := AgentConfigNativeOTLPMarkedRemoved; !ValidAgentConfigStatus(code) {
		t.Fatalf("%s is not a valid agent config status", code)
	}
	if text, ok := AgentConfigNotice("codex", `HOST\u`, AgentConfigNativeOTLPMarkedRemoved); !ok || !strings.Contains(text, NativeOTLPMarkedOrphanBackupSuffix) {
		t.Fatalf("notice = %q, %v", text, ok)
	}
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if NativeOTLPMarkedOrphanRemoved(dataDir, "codex") {
		t.Fatal("note still reported after the account deleted the copy")
	}
}
