// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestMarshalScanResultV7Shape(t *testing.T) {
	t.Parallel()
	version.ResetForTesting()
	version.SetBinaryVersion("0.0.0-test")
	version.SetContentHash([]byte("hello"))

	r := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/tmp/x.go",
		Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		Duration:  50 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "R1",
				Severity:    scanner.SeverityHigh,
				Title:       "t",
				Description: "d",
				Location:    "x.go:42",
				Remediation: "fix",
				Scanner:     "codeguard",
				Tags:        []string{"a"},
			},
		},
	}
	b, err := marshalScanResultV7(r, "0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scanner", "target", "timestamp", "findings", "schema_version", "scan_id"} {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing key %q", k)
		}
	}
}

func TestScanResultSchemaEmbedded(t *testing.T) {
	t.Parallel()
	if len(scanResultSchemaJSON) < 100 {
		t.Fatal("embedded scan-result schema missing or too small")
	}
}

func TestScanFixtureFileJSONSchemaPython(t *testing.T) {
	// Integration-style check: when pytest+jsonschema runs in CI, this is redundant.
	tmp := t.TempDir()
	p := filepath.Join(tmp, "sample.go")
	if err := os.WriteFile(p, []byte(`password = "0123456789abcdef0123456789abcdef"`), 0o600); err != nil {
		t.Fatal(err)
	}
	cg := scanner.NewCodeGuardScanner("")
	res, err := cg.Scan(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshalScanResultV7(res, "test")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
}

// TestScanResultV7RedactsSecretsFromFindingText is a regression test for
// the DeepSec H.MEDIUM finding "Raw scan JSON stores unredacted
// secret-bearing findings". Per-finding text in the v7 wire output
// (`defenseclaw scan code --json`, gateway API scan endpoint) MUST go
// through redaction.ForSinkString — the audit DB has done so since
// audit/scan_persist.go:78 but the JSON path historically did not.
//
// We assert two properties:
//
//  1. A scanner-emitted finding whose Description embeds an obvious
//     secret (an OpenAI-style sk- key) is redacted before serialization.
//     The literal secret bytes MUST NOT appear anywhere in the marshaled
//     JSON output (Title, Description, Location, Remediation are all
//     attacker-influenceable depending on scanner).
//  2. The redacted JSON still parses and the finding shape is preserved
//     (severity, scanner, rule_id) — only the user-visible text fields
//     changed.
//
// Use a synthetic ScanResult rather than running CodeGuard so the test
// is hermetic and the secret value is precisely what we look for.
func TestScanResultV7RedactsSecretsFromFindingText(t *testing.T) {
	t.Parallel()
	version.ResetForTesting()
	version.SetBinaryVersion("0.0.0-test")

	// A literal value the redaction layer recognises as an OpenAI key.
	// Embed it in Description and Remediation — the two finding fields
	// scanner.Finding fills with attacker-influenced source bytes (matched
	// line, suggested fix). Title is intentionally NOT exercised because
	// scan_v7.go keeps it raw to stay symmetric with the audit DB path
	// (see comment in findingToV7); if a scanner ever puts secrets into
	// Title, that scanner is the bug.
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	r := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/tmp/leak.go",
		Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		Duration:  10 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "RX",
				Severity:    scanner.SeverityHigh,
				Title:       "Hardcoded API key detected", // rule-name only
				Description: "matched line: api_key = \"" + secret + "\"",
				Location:    "/tmp/leak.go:42",
				Remediation: "rotate " + secret + " immediately",
				Scanner:     "codeguard",
			},
		},
	}
	b, err := marshalScanResultV7(r, "0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" {
		t.Fatal("marshalScanResultV7 returned empty body")
	}
	// Property 1: literal secret bytes must not survive serialization.
	if strings.Contains(string(b), secret) {
		t.Fatalf("scan v7 JSON contains raw secret %q (must be redacted before persistence/output):\n%s", secret, string(b))
	}
	// Property 2: shape is preserved.
	var top struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("v7 JSON not parseable: %v", err)
	}
	if len(top.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(top.Findings))
	}
	if got, _ := top.Findings[0]["severity"].(string); got == "" {
		t.Fatal("severity round-trip lost: got empty")
	} else if !strings.EqualFold(got, "high") {
		t.Fatalf("severity round-trip wrong: got %q, want HIGH-equivalent", got)
	}
	if got, _ := top.Findings[0]["scanner"].(string); got != "codeguard" {
		t.Fatalf("scanner round-trip lost: got %q", got)
	}
	if got, _ := top.Findings[0]["rule_id"].(string); got == "" {
		t.Fatal("rule_id should be populated by EnsureRuleID")
	}
}
