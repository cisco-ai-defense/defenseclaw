// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestParsePluginOutput_RealFormat verifies that parsePluginOutput correctly
// handles the JSON output from the Python plugin scanner CLI
// (defenseclaw plugin scan --json).
func TestParsePluginOutput_RealFormat(t *testing.T) {
	raw := []byte(`{
		"scanner": "plugin-scanner",
		"target": "/tmp/test-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [
			{
				"id": "plugin-1",
				"rule_id": "PERM-DANGEROUS",
				"severity": "HIGH",
				"confidence": 0.9,
				"title": "Dangerous permission: fs:*",
				"description": "Plugin requests broad filesystem access",
				"evidence": "\"permissions\": [\"fs:*\"]",
				"location": "package.json",
				"remediation": "Request specific file paths instead of fs:*",
				"scanner": "plugin-scanner",
				"tags": ["permissions"],
				"taxonomy": {"objective": "OB-009", "technique": "AITech-9.1"},
				"occurrence_count": 1,
				"suppressed": false
			},
			{
				"id": "plugin-2",
				"rule_id": "SRC-EVAL",
				"severity": "CRITICAL",
				"confidence": 0.95,
				"title": "Dynamic code execution via eval()",
				"description": "eval() can execute arbitrary code",
				"evidence": "eval(userInput)",
				"location": "src/index.ts:42",
				"remediation": "Remove eval() usage",
				"scanner": "plugin-scanner",
				"tags": ["code-execution"],
				"taxonomy": {"objective": "OB-005", "technique": "AITech-5.1"},
				"occurrence_count": 1,
				"suppressed": false
			},
			{
				"id": "plugin-3",
				"rule_id": "SRC-CRED",
				"severity": "MEDIUM",
				"confidence": 0.7,
				"title": "Possible credential access",
				"description": "Reads credential files",
				"location": "src/helper.ts:10",
				"scanner": "plugin-scanner",
				"tags": ["credential-theft"],
				"occurrence_count": 1,
				"suppressed": true,
				"suppression_reason": "false positive"
			}
		],
		"duration_ns": 150000000,
		"metadata": {
			"manifest_name": "test-plugin",
			"manifest_version": "1.0.0",
			"file_count": 5,
			"total_size_bytes": 12345,
			"has_lockfile": true,
			"has_install_scripts": false,
			"detected_capabilities": ["eval", "fs"]
		},
		"assessment": {
			"verdict": "malicious",
			"confidence": 0.95,
			"summary": "Plugin has 1 critical finding(s).",
			"categories": []
		}
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	// Should have 2 findings (3rd is suppressed)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (1 suppressed), got %d", len(findings))
	}

	// Verify first finding
	if findings[0].ID != "plugin-1" {
		t.Errorf("finding[0].ID = %q, want plugin-1", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("finding[0].Severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[0].Title != "Dangerous permission: fs:*" {
		t.Errorf("finding[0].Title = %q", findings[0].Title)
	}
	if findings[0].Location != "package.json" {
		t.Errorf("finding[0].Location = %q, want package.json", findings[0].Location)
	}
	if len(findings[0].Tags) != 1 || findings[0].Tags[0] != "permissions" {
		t.Errorf("finding[0].Tags = %v, want [permissions]", findings[0].Tags)
	}
	if findings[0].Confidence != 0.9 {
		t.Errorf("finding[0].Confidence = %v, want 0.9", findings[0].Confidence)
	}
	if findings[0].EvidenceSummary != `"permissions": ["fs:*"]` {
		t.Errorf("finding[0].EvidenceSummary = %q", findings[0].EvidenceSummary)
	}

	// Verify second finding (CRITICAL)
	if findings[1].Severity != SeverityCritical {
		t.Errorf("finding[1].Severity = %q, want CRITICAL", findings[1].Severity)
	}

	// Verify MaxSeverity works with parsed findings
	result := &ScanResult{Findings: findings}
	if result.MaxSeverity() != SeverityCritical {
		t.Errorf("MaxSeverity = %q, want CRITICAL", result.MaxSeverity())
	}
	if result.IsClean() {
		t.Error("expected not clean")
	}
}

func TestParsePluginOutput_EmptyFindings(t *testing.T) {
	raw := []byte(`{
		"scanner": "plugin-scanner",
		"target": "/tmp/clean-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [],
		"duration_ns": 50000000,
		"assessment": {
			"verdict": "benign",
			"confidence": 0.9,
			"summary": "No security issues detected.",
			"categories": []
		}
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}

	result := &ScanResult{Findings: findings}
	if !result.IsClean() {
		t.Error("expected clean scan")
	}
}

// resolvePluginCLI picks the CLI the integration test drives and reports
// whether it was chosen on purpose (strict) rather than found on PATH.
func resolvePluginCLI() (binary string, strict bool) {
	if envBin := os.Getenv("DEFENSECLAW_BIN"); envBin != "" {
		return envBin, true
	}
	// Prefer repo .venv so we do not invoke a stale global install.
	cand := filepath.Join("..", "..", ".venv", "bin", "defenseclaw")
	if st, err := os.Stat(cand); err == nil && !st.IsDir() {
		return cand, true
	}
	return "defenseclaw", false
}

// errPluginCLINotLaunchable marks a CLI the operating system could not run at
// all: the file or its interpreter is missing, or a shell launcher reported
// the POSIX "cannot execute" (126) or "not found" (127) status. Only this
// outcome means "not installed". A CLI that ran and then failed or hung is a
// real defect and is never reported through this error.
var errPluginCLINotLaunchable = errors.New("plugin CLI cannot be launched")

// pluginCLIStarts runs the CLI with --help (no scan). It returns an error
// wrapping errPluginCLINotLaunchable when the CLI cannot be launched, a plain
// error when it launched but exited nonzero or did not finish in time, and
// nil when it answered.
func pluginCLIStarts(binary string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "--help").CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(output))
	if ctx.Err() != nil {
		return fmt.Errorf("plugin CLI %s did not answer --help within %s: %w: %s", binary, timeout, err, detail)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code == 126 || code == 127 {
			return fmt.Errorf("%w: exit %d: %s", errPluginCLINotLaunchable, code, detail)
		}
		return fmt.Errorf("plugin CLI %s exited %d from --help: %s", binary, exit.ExitCode(), detail)
	}
	return fmt.Errorf("%w: %v", errPluginCLINotLaunchable, err)
}

// gatePluginCLI decides what the integration test does with the CLI it
// picked. A CLI chosen on purpose (DEFENSECLAW_BIN or the repo .venv) must
// start: a broken one is a real failure. A CLI found only on PATH can be a
// stale install on a shared box (its interpreter removed with the tree it was
// built from); only that, "cannot be launched", means skip. A PATH CLI that
// launched and then failed or hung is still a failure.
func gatePluginCLI(binary string, strict bool, timeout time.Duration) (skip bool, err error) {
	err = pluginCLIStarts(binary, timeout)
	return err != nil && !strict && errors.Is(err, errPluginCLINotLaunchable), err
}

func TestGatePluginCLISkipsOnlyAnAbsentPathInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell shims are a Unix install shape")
	}
	dir := t.TempDir()
	script := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	absent := filepath.Join(dir, "missing")
	broken := script("broken", "#!/bin/sh\nexit 23\n")
	working := script("working", "#!/bin/sh\nexit 0\n")
	for _, tc := range []struct {
		name     string
		binary   string
		strict   bool
		wantSkip bool
		wantErr  bool
	}{
		{"path install that is absent skips", absent, false, true, true},
		{"path install that exits nonzero fails", broken, false, false, true},
		{"explicit install that is absent fails", absent, true, false, true},
		{"explicit install that exits nonzero fails", broken, true, false, true},
		{"working path install runs", working, false, false, false},
		{"working explicit install runs", working, true, false, false},
	} {
		skip, err := gatePluginCLI(tc.binary, tc.strict, time.Minute)
		if skip != tc.wantSkip || (err != nil) != tc.wantErr {
			t.Errorf("%s: skip=%v err=%v, want skip=%v err=%v", tc.name, skip, err, tc.wantSkip, tc.wantErr)
		}
	}
}

func TestPluginCLIStartsRejectsAStaleInstallAndAcceptsAWorkingOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shebang shims are a Unix install shape")
	}
	dir := t.TempDir()
	script := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	stale := script("stale", "#!"+filepath.Join(dir, "removed-venv", "bin", "python")+"\nprint(1)\n")
	if err := pluginCLIStarts(stale, time.Minute); !errors.Is(err, errPluginCLINotLaunchable) {
		t.Fatalf("a shim whose interpreter was removed must count as not installed, got %v", err)
	}
	launcher := script("launcher", "#!/bin/sh\nexit 127\n")
	if err := pluginCLIStarts(launcher, time.Minute); !errors.Is(err, errPluginCLINotLaunchable) {
		t.Fatalf("a launcher reporting command-not-found must count as not installed, got %v", err)
	}
	if err := pluginCLIStarts(filepath.Join(dir, "missing"), time.Minute); !errors.Is(err, errPluginCLINotLaunchable) {
		t.Fatalf("a missing file must count as not installed, got %v", err)
	}
	broken := script("broken", "#!/bin/sh\necho boom >&2\nexit 23\n")
	if err := pluginCLIStarts(broken, time.Minute); err == nil || errors.Is(err, errPluginCLINotLaunchable) {
		t.Fatalf("a CLI that starts and exits nonzero is broken, not absent, got %v", err)
	}
	hung := script("hung", "#!/bin/sh\nexec sleep 30\n")
	if err := pluginCLIStarts(hung, 200*time.Millisecond); err == nil || errors.Is(err, errPluginCLINotLaunchable) {
		t.Fatalf("a CLI that does not answer in time is broken, not absent, got %v", err)
	}
	working := script("working", "#!/bin/sh\nexit 0\n")
	if err := pluginCLIStarts(working, time.Minute); err != nil {
		t.Fatalf("a CLI that starts must pass: %v", err)
	}
}

func TestResolvePluginCLIKeepsExplicitChoicesStrict(t *testing.T) {
	t.Setenv("DEFENSECLAW_BIN", "/explicit/defenseclaw")
	if binary, strict := resolvePluginCLI(); binary != "/explicit/defenseclaw" || !strict {
		t.Fatalf("explicit DEFENSECLAW_BIN = (%q, %v), want strict", binary, strict)
	}
}

// TestPluginScanner_Integration calls the real Python CLI and verifies
// Go can parse its output end-to-end. Skipped if defenseclaw is not installed.
func TestPluginScanner_Integration(t *testing.T) {
	binary, strict := resolvePluginCLI()
	if _, err := exec.LookPath(binary); err != nil {
		if _, err2 := os.Stat(binary); err2 != nil {
			t.Skipf("skipping: %s not found: %v", binary, err)
		}
	}
	if skip, err := gatePluginCLI(binary, strict, 2*time.Minute); err != nil {
		if skip {
			t.Skipf("skipping: defenseclaw on PATH (%s) is not installed: %v", binary, err)
		}
		t.Fatalf("plugin scanner CLI %s does not start: %v", binary, err)
	}

	// The target CLI is v8-only and its scan occurrence must enter the
	// process-owned runtime rather than a private Python SQLite writer. Give the
	// integration a real HTTP acknowledgement boundary so it does not inherit a
	// developer's machine config or silently bypass canonical admission.
	emitted := make(chan []byte, 1)
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/observability/cli" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		emitted <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(runtime.Close)
	runtimeURL, err := url.Parse(runtime.URL)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configSource := fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  api_bind: %s\n  api_port: %s\n  token: integration-token\nobservability: {}\n",
		filepath.Dir(configPath), runtimeURL.Hostname(), runtimeURL.Port(),
	)
	if err := os.WriteFile(configPath, []byte(configSource), 0o600); err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	gatewayBinary := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	buildGateway := exec.Command("go", "build", "-o", gatewayBinary, "./cmd/defenseclaw")
	buildGateway.Dir = repositoryRoot
	if output, err := buildGateway.CombinedOutput(); err != nil {
		t.Fatalf("build current gateway config helper: %v: %s", err, output)
	}
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	t.Setenv("DEFENSECLAW_GATEWAY_BIN", gatewayBinary)

	scanner := NewPluginScanner(binary)

	// Scan this repo's extensions/defenseclaw directory as a real target
	target := "../../extensions/defenseclaw"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("skipping: target %s not found", target)
	}

	// The Go caller records every scan it runs, so the CLI child must not
	// emit the same scan a second time (GAP-2482).
	awaitEmission := func(scanName string) {
		t.Helper()
		select {
		case <-emitted:
			t.Fatalf("%s scan was recorded by the CLI child as well as the caller", scanName)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Default scans recognize the bundled first-party extension by canonical
	// identity and must not report its own signatures/runtime as malware.
	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("default Scan failed: %v", err)
	}

	if result.Scanner != "plugin-scanner" {
		t.Errorf("Scanner = %q, want plugin-scanner", result.Scanner)
	}
	if result.Target != target {
		t.Errorf("Target = %q, want %q", result.Target, target)
	}
	awaitEmission("default")
	if len(result.Findings) != 0 {
		t.Fatalf("default self scan returned %d findings, want 0", len(result.Findings))
	}

	// Developers can explicitly audit DefenseClaw itself. This second pass
	// preserves the real analyzer and Go JSON-parser coverage.
	scanner.IncludeSelf = true
	result, err = scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("include-self Scan failed: %v", err)
	}
	awaitEmission("include-self")
	// The extension has real findings (child_process import, localhost refs, etc.)
	if len(result.Findings) == 0 {
		t.Error("expected at least 1 finding from scanning extensions/defenseclaw")
	}
	for i, f := range result.Findings {
		if f.ID == "" {
			t.Errorf("finding[%d].ID is empty", i)
		}
		if f.Severity == "" {
			t.Errorf("finding[%d].Severity is empty", i)
		}
		if f.Title == "" {
			t.Errorf("finding[%d].Title is empty", i)
		}
	}

	t.Logf("OK: %d findings, max severity = %s", len(result.Findings), result.MaxSeverity())
}

func TestParsePluginOutput_AllSuppressed(t *testing.T) {
	raw := []byte(`{
		"scanner": "plugin-scanner",
		"target": "/tmp/suppressed-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [
			{
				"id": "plugin-1",
				"severity": "HIGH",
				"title": "False positive",
				"description": "Not a real issue",
				"scanner": "plugin-scanner",
				"suppressed": true,
				"suppression_reason": "known safe"
			}
		]
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (all suppressed), got %d", len(findings))
	}
}

func TestPluginScanCommand(t *testing.T) {
	t.Run("default cli path uses plugin subcommand", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: ""}
		binary, args := s.pluginScanCommand("/tmp/plugin")
		if binary != "defenseclaw" {
			t.Fatalf("binary = %q, want defenseclaw", binary)
		}
		want := []string{"plugin", "scan", "--json", "/tmp/plugin"}
		if len(args) != len(want) {
			t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
			}
		}
	})

	t.Run("legacy standalone scanner remains supported", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "/usr/local/bin/defenseclaw-plugin-scanner"}
		binary, args := s.pluginScanCommand("/tmp/plugin")
		if binary != "/usr/local/bin/defenseclaw-plugin-scanner" {
			t.Fatalf("binary = %q", binary)
		}
		if len(args) != 1 || args[0] != "/tmp/plugin" {
			t.Fatalf("args = %v, want [/tmp/plugin]", args)
		}
	})

	t.Run("policy and profile flags are appended", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "defenseclaw", Policy: "strict", Profile: "enterprise"}
		_, args := s.pluginScanCommand("/tmp/plugin")
		want := []string{"plugin", "scan", "--json", "/tmp/plugin", "--policy", "strict", "--profile", "enterprise"}
		if len(args) != len(want) {
			t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
			}
		}
	})

	t.Run("include self is explicit", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "defenseclaw", IncludeSelf: true}
		_, args := s.pluginScanCommand("/tmp/plugin")
		want := []string{"plugin", "scan", "--json", "/tmp/plugin", "--include-self"}
		if len(args) != len(want) {
			t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
			}
		}
	})
}
