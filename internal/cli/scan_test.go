// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
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
