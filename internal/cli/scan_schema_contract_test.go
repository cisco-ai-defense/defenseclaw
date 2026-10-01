// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	scanResultSchemaID = "https://defenseclaw.io/schemas/scan-result.json"
	// scanCodeJSONGolden is a representative `scan code --json` document.
	// The Python suite validates it with the Python jsonschema implementation
	// that downstream consumers use, so the Python shard never has to compile
	// the Go CLI. This test keeps the document tied to the real command output.
	scanCodeJSONGolden = "testdata/scan-code-json.golden.json"
)

// TestScanCodeJSONCommandValidatesCanonicalSchema runs the real
// `scan code --json` command path in-process and validates the bytes it
// writes against the canonical schemas/scan-result.json.
func TestScanCodeJSONCommandValidatesCanonicalSchema(t *testing.T) {
	canonical, err := os.ReadFile(filepath.Join("..", "..", "schemas", "scan-result.json"))
	if err != nil {
		t.Fatalf("read canonical scan-result schema: %v", err)
	}
	if !bytes.Equal(canonical, scanResultSchemaJSON) {
		t.Fatal("embedded scan-result schema differs from schemas/scan-result.json")
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource(scanResultSchemaID, bytes.NewReader(canonical)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(scanResultSchemaID)
	if err != nil {
		t.Fatalf("compile scan-result schema: %v", err)
	}

	goldenBytes, err := os.ReadFile(scanCodeJSONGolden)
	if err != nil {
		t.Fatal(err)
	}
	golden := decodeScanDocument(t, goldenBytes)
	if err := schema.Validate(golden); err != nil {
		t.Fatalf("%s does not validate: %v", scanCodeJSONGolden, err)
	}
	goldenFindings := golden["findings"].([]any)
	if len(goldenFindings) != 1 {
		t.Fatalf("%s must carry exactly one finding, got %d", scanCodeJSONGolden, len(goldenFindings))
	}

	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	previousJSON, previousRaw, previousSchema := scanOutputJSON, scanNoRedact, scanPrintSchema
	t.Cleanup(func() {
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
		scanOutputJSON, scanNoRedact, scanPrintSchema = previousJSON, previousRaw, previousSchema
	})
	localConfig := config.DefaultConfig()
	localConfig.DataDir = ""
	localConfig.Scanners.CodeGuard = ""
	cfg, auditStore, auditLog = localConfig, nil, nil
	scanOutputJSON, scanNoRedact, scanPrintSchema = true, false, false
	for _, key := range []string{
		"DEFENSECLAW_AGENT_ID", "DEFENSECLAW_AGENT_INSTANCE_ID", "DEFENSECLAW_SIDECAR_INSTANCE_ID",
	} {
		t.Setenv(key, "")
	}

	for _, fixture := range []struct {
		name, file, body string
		wantFindings     bool
	}{
		{name: "clean", file: "x.go", body: "package x\nvar _ = \"x\"\n"},
		{name: "finding", file: "exec.py", body: "import os\nos.system(cmd)\n", wantFindings: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), fixture.file)
			if err := os.WriteFile(target, []byte(fixture.body), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&stdout)
			if err := runScanCode(command, []string{target}); err != nil {
				t.Fatalf("scan code --json: %v", err)
			}
			document := decodeScanDocument(t, stdout.Bytes())
			if err := schema.Validate(document); err != nil {
				t.Fatalf("scan code --json output does not validate: %v\n%s", err, stdout.String())
			}
			if got, want := sortedKeys(document), sortedKeys(golden); !slices.Equal(got, want) {
				t.Fatalf("envelope keys drifted from %s: got %v, want %v", scanCodeJSONGolden, got, want)
			}
			findings := document["findings"].([]any)
			if fixture.wantFindings != (len(findings) > 0) {
				t.Fatalf("findings = %d, want findings: %v\n%s", len(findings), fixture.wantFindings, stdout.String())
			}
			for _, finding := range findings {
				got := sortedKeys(finding.(map[string]any))
				want := sortedKeys(goldenFindings[0].(map[string]any))
				if !slices.Equal(got, want) {
					t.Fatalf("finding keys drifted from %s: got %v, want %v", scanCodeJSONGolden, got, want)
				}
			}
		})
	}
}

func decodeScanDocument(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode scan document: %v\n%s", err, body)
	}
	return document
}

func sortedKeys(document map[string]any) []string {
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
