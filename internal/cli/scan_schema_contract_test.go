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
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
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

// TestScanCodeJSONCommandValidatesCanonicalSchema checks the `scan code
// --json` output contract against the canonical schemas/scan-result.json.
//
// The clean and finding subtests run runScanCode in-process with no audit
// store and capture the command's writer, so the schema and key checks do no
// I/O beyond the fixture. The command_tree subtest runs `scan code <file>
// --json` once through rootCmd: cobra flag parsing, the root pre-run with an
// isolated v8 config and audit store, and the persisted-scan branch. It
// captures the process stdout, so it fails if anything other than the single
// JSON document reaches it.
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

	// checkContract validates one command output and returns its findings.
	checkContract := func(t *testing.T, document map[string]any, out []byte, wantFindings bool) []any {
		t.Helper()
		if err := schema.Validate(document); err != nil {
			t.Fatalf("scan code --json output does not validate: %v\n%s", err, out)
		}
		if got, want := sortedKeys(document), sortedKeys(golden); !slices.Equal(got, want) {
			t.Fatalf("envelope keys drifted from %s: got %v, want %v", scanCodeJSONGolden, got, want)
		}
		findings := document["findings"].([]any)
		if wantFindings != (len(findings) > 0) {
			t.Fatalf("findings = %d, want findings: %v\n%s", len(findings), wantFindings, out)
		}
		want := sortedKeys(goldenFindings[0].(map[string]any))
		for _, finding := range findings {
			if got := sortedKeys(finding.(map[string]any)); !slices.Equal(got, want) {
				t.Fatalf("finding keys drifted from %s: got %v, want %v", scanCodeJSONGolden, got, want)
			}
		}
		return findings
	}

	for _, fixture := range []struct {
		name, file, body string
		wantFindings     bool
	}{
		{name: "clean", file: "x.go", body: "package x\nvar _ = \"x\"\n"},
		{name: "finding", file: "exec.py", body: scanCodeFindingFixture, wantFindings: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			useStorelessScanConfig(t)
			target := writeScanCodeFixture(t, fixture.file, fixture.body)
			var stdout bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&stdout)
			if err := runScanCode(command, []string{target}); err != nil {
				t.Fatalf("scan code --json: %v", err)
			}
			checkContract(t, decodeScanDocument(t, stdout.Bytes()), stdout.Bytes(), fixture.wantFindings)
		})
	}

	t.Run("command_tree", func(t *testing.T) {
		isolateScanCodeCommand(t)
		dataDir := isolatedScanCodeHome(t)
		target := writeScanCodeFixture(t, "exec.py", scanCodeFindingFixture)

		stdout := redirectProcessStdout(t)
		rootCmd.SetArgs([]string{"scan", "code", target, "--json"})
		_, runErr := rootCmd.ExecuteC()
		out := stdout()
		if runErr != nil {
			t.Fatalf("scan code --json: %v\nstdout:\n%s", runErr, out)
		}
		document := decodeSoleScanDocument(t, out)
		findings := checkContract(t, document, out, true)

		// The root pre-run must have loaded the isolated config and the
		// command must have persisted the scan it reported: the scan_id on
		// stdout is the one taken from the persisted copy.
		if cfg == nil || !strings.HasPrefix(cfg.AuditDB, dataDir) {
			t.Fatalf("the pre-run did not load the isolated config in %s", dataDir)
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

const scanCodeFindingFixture = "import os\nos.system(cmd)\n"

func writeScanCodeFixture(t *testing.T, name, body string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return target
}

// useStorelessScanConfig points the scan globals at a default config with no
// data dir or audit store, as runScanCode sees them without the root pre-run.
func useStorelessScanConfig(t *testing.T) {
	t.Helper()
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
}

// isolateScanCodeCommand snapshots and restores the package and command-tree
// state that executing `scan code` through rootCmd mutates, including the
// audit store the root pre-run opens.
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
		// The post-run closes the store the pre-run opened, but only on
		// success; close it here too so a failing run cannot leak the handle
		// into later tests or keep the data dir busy on Windows.
		if auditStore != nil && auditStore != previousStore {
			_ = auditStore.Close()
		}
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
// a fresh minimal v8 config and returns its data dir. The data dir comes from
// testenv.PrivateTempDir: the pre-run refuses an audit store directory the
// current user does not own, and some Windows images make the Administrators
// group the owner of directories created under the shared temp tree.
func isolatedScanCodeHome(t *testing.T) string {
	t.Helper()
	home := testenv.PrivateTempDir(t)
	dataDir := testenv.PrivateTempDir(t)
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
