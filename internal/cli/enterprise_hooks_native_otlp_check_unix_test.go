//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1360 (verify half): managed Unix verify runs the check managed Windows
// verify runs. The real as-the-user worker names the Codex and Claude Code
// exporters of an eligible account that carry the product gateway token,
// changes nothing, and reports a configuration it may not read (one that
// leads out of the home) instead of passing it.
func TestNativeOTLPCheckNamesTheProductExporterOfAnEligibleAccountAndChangesNothing(t *testing.T) {
	home := foreignCleanupRealWorkerPass(t, true)
	digest, _ := connector.NativeOTLPCredentialDigestOf(gap2376ProductToken)
	previous := enterpriseHookStandaloneProductCredentialDigests
	t.Cleanup(func() { enterpriseHookStandaloneProductCredentialDigests = previous })
	enterpriseHookStandaloneProductCredentialDigests = func() []connector.NativeOTLPCredentialDigest {
		return []connector.NativeOTLPCredentialDigest{digest}
	}
	codex := filepath.Join(home, ".codex", "config.toml")
	claude := filepath.Join(home, ".claude", "settings.json")
	bodies := map[string]string{
		codex: "model = \"gpt-5\"\n\n[otel.exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18971/v1/logs\"\n\n" +
			"[otel.exporter.otlp-http.headers]\nAuthorization = \"Bearer " + gap2376ProductToken + "\"\n\n" +
			"[otel.trace_exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18972/v1/traces\"\n\n" +
			"[otel.trace_exporter.otlp-http.headers]\nAuthorization = \"Bearer foreign-collector-0123456789abcdef\"\n",
		claude: `{"model":"haiku","env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:18971",` +
			`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer ` + gap2376ProductToken + `"}}`,
	}
	for path, body := range bodies {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report := checkEnterpriseHookStandaloneNativeOTLP(context.Background())
	if !report.OK || report.Accounts != 1 || len(report.Findings) != 2 {
		t.Fatalf("report = %+v, want two findings for the one eligible account", report)
	}
	for _, finding := range report.Findings {
		if finding.Error != "" || len(finding.Entries) == 0 || finding.Path != bodies2path(finding.Connector, codex, claude) {
			t.Fatalf("finding = %+v, want the exporter entries of %s", finding, finding.Connector)
		}
		for _, entry := range finding.Entries {
			if strings.Contains(entry, gap2376ProductToken) {
				t.Fatalf("a finding carries the credential: %+v", finding)
			}
		}
	}
	for path, body := range bodies {
		if got, _ := os.ReadFile(path); string(got) != body {
			t.Fatalf("the check changed %s:\n%s", path, got)
		}
	}

	// The user's own exporter alone is no finding.
	own := "model = \"gpt-5\"\n\n[otel.trace_exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18972/v1/traces\"\n\n" +
		"[otel.trace_exporter.otlp-http.headers]\nAuthorization = \"Bearer foreign-collector-0123456789abcdef\"\n"
	if err := os.WriteFile(codex, []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(claude); err != nil {
		t.Fatal(err)
	}
	if report := checkEnterpriseHookStandaloneNativeOTLP(context.Background()); !report.OK || len(report.Findings) != 0 {
		t.Fatalf("the user's own exporter was reported: %+v", report)
	}

	// A configuration that leads out of the home is reported unchecked.
	if err := os.Remove(codex); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, []byte(bodies[codex]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, codex); err != nil {
		t.Fatal(err)
	}
	report = checkEnterpriseHookStandaloneNativeOTLP(context.Background())
	if !report.OK || len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Error, "outside the enrolled home") {
		t.Fatalf("a config outside the home was not reported: %+v", report)
	}
}

func bodies2path(name, codex, claude string) string {
	if name == "codex" {
		return codex
	}
	return claude
}
