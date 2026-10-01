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
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const (
	scanResultSchemaID = "https://defenseclaw.io/schemas/scan-result.json"
	// scanCodeJSONGolden is a representative `scan code --json` document.
	// The Python suite validates it with the Python jsonschema implementation
	// that downstream consumers use, so the Python shard never has to compile
	// the Go CLI. This test keeps the document tied to the real command output.
	scanCodeJSONGolden = "testdata/scan-code-json.golden.json"
)

// TestScanCodeJSONCommandValidatesCanonicalSchema runs `defenseclaw scan code
// <target> --json` through the real command tree in-process: cobra flag
// parsing, the root pre-run (isolated v8 config load, audit store open) and the
// persisted-scan branch. It captures the process stdout itself, so the test
// fails if anything other than the single JSON document reaches it, and it
// validates that document against the canonical schemas/scan-result.json.
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

	isolateScanCodeCommand(t)

	for _, fixture := range []struct {
		name, file, body string
		wantFindings     bool
	}{
		{name: "clean", file: "x.go", body: "package x\nvar _ = \"x\"\n"},
		{name: "finding", file: "exec.py", body: "import os\nos.system(cmd)\n", wantFindings: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			dataDir := isolatedScanCodeHome(t)
			// The post-run closes the store the pre-run opened, but only on
			// success; close it here too so a failing run cannot leak the
			// handle into later tests or keep the temp dir busy on Windows.
			storeBefore := auditStore
			t.Cleanup(func() {
				if auditStore != nil && auditStore != storeBefore {
					_ = auditStore.Close()
				}
			})
			target := filepath.Join(t.TempDir(), fixture.file)
			if err := os.WriteFile(target, []byte(fixture.body), 0o600); err != nil {
				t.Fatal(err)
			}

			stdout := redirectProcessStdout(t)
			rootCmd.SetArgs([]string{"scan", "code", target, "--json"})
			_, runErr := rootCmd.ExecuteC()
			out := stdout()
			if runErr != nil {
				t.Fatalf("scan code --json: %v\nstdout:\n%s", runErr, out)
			}

			document := decodeSoleScanDocument(t, out)
			if err := schema.Validate(document); err != nil {
				t.Fatalf("scan code --json output does not validate: %v\n%s", err, out)
			}
			if got, want := sortedKeys(document), sortedKeys(golden); !slices.Equal(got, want) {
				t.Fatalf("envelope keys drifted from %s: got %v, want %v", scanCodeJSONGolden, got, want)
			}
			findings := document["findings"].([]any)
			if fixture.wantFindings != (len(findings) > 0) {
				t.Fatalf("findings = %d, want findings: %v\n%s", len(findings), fixture.wantFindings, out)
			}
			for _, finding := range findings {
				got := sortedKeys(finding.(map[string]any))
				want := sortedKeys(goldenFindings[0].(map[string]any))
				if !slices.Equal(got, want) {
					t.Fatalf("finding keys drifted from %s: got %v, want %v", scanCodeJSONGolden, got, want)
				}
			}

			// The root pre-run must have loaded the isolated config and the
			// command must have persisted the scan it reported: the scan_id on
			// stdout is the one taken from the persisted copy.
			if cfg == nil || !strings.HasPrefix(cfg.AuditDB, dataDir) {
				t.Fatalf("audit store %v is not inside the isolated data dir %s", cfg, dataDir)
			}
			scanID, _ := document["scan_id"].(string)
			if scanID == "" {
				t.Fatalf("scan code --json carried no scan_id\n%s", out)
			}
			store, err := audit.NewStore(cfg.AuditDB)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if raw, err := store.GetScanRawJSON(scanID); err != nil || raw == "" {
				t.Fatalf("scan %s was not persisted: raw=%q err=%v", scanID, raw, err)
			}
			rows, err := store.ListScanFindings(scanID)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != len(findings) {
				t.Fatalf("persisted %d findings for scan %s, stdout reported %d", len(rows), scanID, len(findings))
			}
		})
	}
}

// isolateScanCodeCommand snapshots and restores the package and command-tree
// state that executing `scan code` through rootCmd mutates.
func isolateScanCodeCommand(t *testing.T) {
	t.Helper()
	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	previousStartup := activeObservabilityV8Startup
	previousJSON, previousRaw, previousSchema := scanOutputJSON, scanNoRedact, scanPrintSchema
	previousBinaryVersion := version.Current().BinaryVersion
	// A writer pinned by an earlier test would bypass the process stdout this
	// test captures; production leaves it unset so output goes to os.Stdout.
	for _, command := range []*cobra.Command{rootCmd, scanCmd, scanCodeCmd} {
		command.SetOut(nil)
	}
	t.Cleanup(func() {
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
		activeObservabilityV8Startup = previousStartup
		rootCmd.SetArgs(nil)
		for _, command := range []*cobra.Command{rootCmd, scanCmd, scanCodeCmd} {
			command.SetOut(nil)
		}
		scanCodeCmd.Flags().VisitAll(func(flag *pflag.Flag) {
			_ = flag.Value.Set(flag.DefValue)
			flag.Changed = false
		})
		scanOutputJSON, scanNoRedact, scanPrintSchema = previousJSON, previousRaw, previousSchema
		// The pre-run wires these to the store it opened; no other test in
		// this package installs them.
		scanner.SetCorrelator(nil)
		scanner.SetFindingEnricher(nil)
		scanner.SetCapabilityEnricher(nil)
		version.SetBinaryVersion(previousBinaryVersion)
	})
	for _, key := range []string{
		daemon.EnvDaemon,
		"DEFENSECLAW_AGENT_ID", "DEFENSECLAW_AGENT_INSTANCE_ID", "DEFENSECLAW_SIDECAR_INSTANCE_ID",
	} {
		t.Setenv(key, "")
	}
}

// isolatedScanCodeHome points HOME, DEFENSECLAW_HOME and DEFENSECLAW_CONFIG at
// a fresh minimal v8 config and returns its data dir.
func isolatedScanCodeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dataDir, "config.yaml")
	quotedDataDir, err := json.Marshal(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	config := "config_version: 8\ndata_dir: " + string(quotedDataDir) + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv(managed.ConfigPathEnv, configPath)
	return dataDir
}

// redirectProcessStdout points os.Stdout at a temp file until the returned
// function is called, which restores it and returns everything written. The
// caller must not run in parallel with other tests.
func redirectProcessStdout(t *testing.T) func() []byte {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = file
	restored := false
	restore := func() {
		if !restored {
			restored = true
			os.Stdout = previous
			_ = file.Close()
		}
	}
	// Registered after t.TempDir, so it runs first and the file is closed
	// before the directory is removed (required on Windows).
	t.Cleanup(restore)
	return func() []byte {
		restore()
		body, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
}

// decodeSoleScanDocument requires stdout to be exactly one JSON document and
// its trailing newline, as JSON consumers of the command read it.
func decodeSoleScanDocument(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("stdout is not a JSON document: %v\n%s", err, body)
	}
	if rest := body[decoder.InputOffset():]; string(rest) != "\n" {
		t.Fatalf("stdout carries %q after the JSON document, want a single newline", rest)
	}
	return document
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
