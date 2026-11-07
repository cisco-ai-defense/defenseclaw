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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
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

// errPluginCLIAbsent marks a CLI whose file, or whose interpreter (the shebang
// target of a console script), is not there: cmd.Start failed because a path
// does not exist, or a bare name matches no regular file on PATH. Only this
// outcome means "not installed". A start failure for any other reason (access
// denied, a resource limit), or a regular file of that name on PATH that
// exec.LookPath passed over because it cannot be executed, means the CLI is
// present and broken. Once the process started, its exit status is the answer of the
// CLI itself, whatever the number: a shell launcher or a script can print its
// output and exit 126 or 127 for its own reasons, so a status cannot show that
// the file was missing. A CLI that ran and then failed or hung is a real defect
// and is never reported through this error.
var errPluginCLIAbsent = errors.New("plugin CLI is not installed")

// pathHoldsANonExecutable reports whether a bare command name matches an
// entry on PATH that exec.LookPath passed over. LookPath returns ErrNotFound
// both for a name with no entry and for an entry it cannot use (no execute
// permission, a symlink that cannot be resolved), so only after a lookup
// failure does an entry by that name mean "present and broken" rather than
// "not installed". It searches the way LookPath does: an empty PATH element
// is the current directory. The one entry that still counts as absent is a
// symlink whose target is gone, which is what a removed install leaves behind.
// An entry that cannot even be looked at (a PATH directory without search
// permission) is not shown absent: the file may be in it, so it counts as
// present and broken. Only "no such entry" and "a PATH element that is not a
// directory" show a name is not there.
// Windows resolves a bare name through PATHEXT, where a file without an
// executable extension is not a candidate.
func pathHoldsANonExecutable(name string) bool {
	if runtime.GOOS == "windows" || strings.ContainsRune(name, '/') {
		return false
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return true
		}
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return true
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}

// pluginCLIStarts runs the CLI with --help (no scan). It returns an error
// wrapping errPluginCLIAbsent when a path it needs does not exist, a plain
// error when it could not start for another reason, started but exited
// nonzero, or did not finish in time, and nil when it answered.
func pluginCLIStarts(binary string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, "--help")
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) && pathHoldsANonExecutable(binary) {
			// LookPath reports a file it cannot execute as not found.
			return fmt.Errorf("plugin CLI %s is on PATH but cannot be executed: %w", binary, err)
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("%w: %v", errPluginCLIAbsent, err)
		}
		return fmt.Errorf("plugin CLI %s is present but cannot be started: %w", binary, err)
	}
	err := cmd.Wait()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(output.String())
	if ctx.Err() != nil {
		return fmt.Errorf("plugin CLI %s did not answer --help within %s: %w: %s", binary, timeout, err, detail)
	}
	return fmt.Errorf("plugin CLI %s failed --help after it started: %w: %s", binary, err, detail)
}

// gatePluginCLI decides what the integration test does with the CLI it
// picked. A CLI chosen on purpose (DEFENSECLAW_BIN or the repo .venv) must
// start: a broken or missing one is a real failure. A CLI found only on PATH
// can be a stale install on a shared box (its interpreter removed with the tree
// it was built from); only that, a missing file or interpreter, means skip. A
// PATH CLI that is present but cannot be started (access denied), or that
// started and then failed (any exit status, 126 and 127 included) or hung, is
// still a failure.
func gatePluginCLI(binary string, strict bool, timeout time.Duration) (skip bool, err error) {
	err = pluginCLIStarts(binary, timeout)
	return err != nil && !strict && errors.Is(err, errPluginCLIAbsent), err
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
	stale := script("stale", "#!"+filepath.Join(dir, "removed-venv", "bin", "python")+"\nprint(1)\n")
	notExecutable := script("not-executable", "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(notExecutable, 0o644); err != nil {
		t.Fatal(err)
	}
	interpreter := script("interpreter-without-execute", "print(1)\n")
	if err := os.Chmod(interpreter, 0o644); err != nil {
		t.Fatal(err)
	}
	cannotRunInterpreter := script("cannot-run-interpreter", "#!"+interpreter+"\nprint(1)\n")
	startedThenNotFound := script("started-127", "#!/bin/sh\necho started --help\nexit 127\n")
	startedThenCannotExec := script("started-126", "#!/bin/sh\necho started --help\nexit 126\n")
	for _, tc := range []struct {
		name     string
		binary   string
		strict   bool
		wantSkip bool
		wantErr  bool
	}{
		{"path install that is absent skips", absent, false, true, true},
		{"path install whose interpreter was removed skips", stale, false, true, true},
		{"path install without the execute bit fails", notExecutable, false, false, true},
		{"path install whose interpreter lacks the execute bit fails", cannotRunInterpreter, false, false, true},
		{"explicit install without the execute bit fails", notExecutable, true, false, true},
		{"path install that exits nonzero fails", broken, false, false, true},
		{"path install that starts and exits 127 fails", startedThenNotFound, false, false, true},
		{"path install that starts and exits 126 fails", startedThenCannotExec, false, false, true},
		{"explicit install that starts and exits 127 fails", startedThenNotFound, true, false, true},
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
	if err := pluginCLIStarts(stale, time.Minute); !errors.Is(err, errPluginCLIAbsent) {
		t.Fatalf("a shim whose interpreter was removed must count as not installed, got %v", err)
	}
	for _, code := range []string{"126", "127"} {
		started := script("started-"+code, "#!/bin/sh\necho started --help\nexit "+code+"\n")
		if err := pluginCLIStarts(started, time.Minute); err == nil || errors.Is(err, errPluginCLIAbsent) {
			t.Fatalf("a CLI that started and exited %s is broken, not absent, got %v", code, err)
		}
	}
	if err := pluginCLIStarts(filepath.Join(dir, "missing"), time.Minute); !errors.Is(err, errPluginCLIAbsent) {
		t.Fatalf("a missing file must count as not installed, got %v", err)
	}
	broken := script("broken", "#!/bin/sh\necho boom >&2\nexit 23\n")
	if err := pluginCLIStarts(broken, time.Minute); err == nil || errors.Is(err, errPluginCLIAbsent) {
		t.Fatalf("a CLI that starts and exits nonzero is broken, not absent, got %v", err)
	}
	hung := script("hung", "#!/bin/sh\nexec sleep 30\n")
	if err := pluginCLIStarts(hung, 200*time.Millisecond); err == nil || errors.Is(err, errPluginCLIAbsent) {
		t.Fatalf("a CLI that does not answer in time is broken, not absent, got %v", err)
	}
	working := script("working", "#!/bin/sh\nexit 0\n")
	if err := pluginCLIStarts(working, time.Minute); err != nil {
		t.Fatalf("a CLI that starts must pass: %v", err)
	}
}

// TestGatePluginCLIChoosesTheBareNameThroughPATH covers the lookup a PATH
// install goes through: the bare name is resolved by exec.LookPath, which
// reports a present file without the execute permission as not found.
func TestGatePluginCLIChoosesTheBareNameThroughPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell shims are a Unix install shape")
	}
	write := func(dir, name, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	const name = "defenseclaw-path-choice"
	for _, tc := range []struct {
		name     string
		setup    func(dir string)
		wantSkip bool
		wantErr  bool
	}{
		{"nothing on PATH skips", func(string) {}, true, true},
		{"a file of another name skips", func(dir string) { write(dir, "other", "#!/bin/sh\nexit 0\n", 0o755) }, true, true},
		{"a directory of that name skips", func(dir string) {
			if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
		}, true, true},
		{"a regular file without the execute bit fails", func(dir string) { write(dir, name, "#!/bin/sh\nexit 0\n", 0o644) }, false, true},
		{"a symlink to a file without the execute bit fails", func(dir string) {
			write(dir, "target", "#!/bin/sh\nexit 0\n", 0o644)
			if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}, false, true},
		{"a dangling symlink skips", func(dir string) {
			if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}, true, true},
		{"a symlink that loops back to itself fails", func(dir string) {
			if err := os.Symlink(filepath.Join(dir, name), filepath.Join(dir, name+"-loop")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, name+"-loop"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}, false, true},
		{"a symlink that loops back to itself fails", func(dir string) {
			if err := os.Symlink(filepath.Join(dir, name), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}, false, true},
		{"a file without the execute bit in the current directory, named by an empty PATH element, fails", func(dir string) {
			write(dir, name, "#!/bin/sh\nexit 0\n", 0o644)
			t.Chdir(dir)
			t.Setenv("PATH", string(os.PathListSeparator)+t.TempDir())
		}, false, true},
		{"an empty PATH element with no such file in the current directory skips", func(dir string) {
			t.Chdir(dir)
			t.Setenv("PATH", string(os.PathListSeparator)+t.TempDir())
		}, true, true},
		{"an executable file runs", func(dir string) { write(dir, name, "#!/bin/sh\nexit 0\n", 0o755) }, false, false},
		{"an executable file later on PATH wins over an earlier non-executable one", func(dir string) {
			first := filepath.Join(dir, "first")
			if err := os.Mkdir(first, 0o755); err != nil {
				t.Fatal(err)
			}
			write(first, name, "#!/bin/sh\nexit 0\n", 0o644)
			write(dir, name, "#!/bin/sh\nexit 0\n", 0o755)
			t.Setenv("PATH", first+string(os.PathListSeparator)+dir)
		}, false, false},
		{"a file that starts and exits nonzero fails", func(dir string) { write(dir, name, "#!/bin/sh\nexit 23\n", 0o755) }, false, true},
	} {
		dir := t.TempDir()
		t.Setenv("PATH", dir)
		tc.setup(dir)
		skip, err := gatePluginCLI(name, false, time.Minute)
		if skip != tc.wantSkip || (err != nil) != tc.wantErr {
			t.Errorf("%s: skip=%v err=%v, want skip=%v err=%v", tc.name, skip, err, tc.wantSkip, tc.wantErr)
		}
	}
}

// TestGatePluginCLIFailsWhenAPathDirectoryCannotBeSearched covers a PATH
// directory the user may not search: the CLI can be inside it, and LookPath
// folds that access error into "not found". The gate cannot show the CLI is
// absent, so it fails; a lookup that finds the CLI elsewhere still runs, and
// entries that show absence (no such directory, an element that is a file)
// still skip.
func TestGatePluginCLIFailsWhenAPathDirectoryCannotBeSearched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell shims are a Unix install shape")
	}
	if os.Geteuid() == 0 {
		t.Skip("root searches every directory")
	}
	const name = "defenseclaw-path-locked"
	locked := func(withCLI bool) string {
		dir := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if withCLI {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		return dir
	}
	working := t.TempDir()
	if err := os.WriteFile(filepath.Join(working, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notADirectory := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADirectory, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathListSeparator)
	for _, tc := range []struct {
		name     string
		path     string
		wantSkip bool
		wantErr  bool
	}{
		{"a directory without search permission that holds the CLI fails", locked(true), false, true},
		{"a directory without search permission that may hold the CLI fails", locked(false), false, true},
		{"the CLI later on PATH runs past a directory without search permission", locked(true) + sep + working, false, false},
		{"a PATH element that does not exist skips", filepath.Join(t.TempDir(), "gone"), true, true},
		{"a PATH element that is a file skips", notADirectory, true, true},
	} {
		t.Setenv("PATH", tc.path)
		skip, err := gatePluginCLI(name, false, time.Minute)
		if skip != tc.wantSkip || (err != nil) != tc.wantErr {
			t.Errorf("%s: skip=%v err=%v, want skip=%v err=%v", tc.name, skip, err, tc.wantSkip, tc.wantErr)
		}
	}
	// The integration test itself, with a defenseclaw behind a directory it
	// cannot search: it fails rather than skipping.
	if binary, strict := resolvePluginCLI(); !strict {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPluginScanner_Integration$", "-test.v")
		cmd.Env = []string{"PATH=" + locked(true), "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
		output, err := cmd.CombinedOutput()
		if err == nil || strings.Contains(string(output), "--- SKIP") || !strings.Contains(string(output), "--- FAIL") {
			t.Fatalf("a PATH directory without search permission must fail the integration test (%s), err=%v:\n%s", binary, err, output)
		}
	}
}

// TestPluginScannerIntegrationDecidesAPathInstallByWhetherItIsPresent runs the
// integration test itself with only a bare "defenseclaw" to find, as on a
// developer's box with no repo .venv and no explicit DEFENSECLAW_BIN.
func TestPluginScannerIntegrationDecidesAPathInstallByWhetherItIsPresent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell shims are a Unix install shape")
	}
	if binary, strict := resolvePluginCLI(); strict {
		t.Skipf("the integration test would use %s, not PATH", binary)
	}
	run := func(setup func(dir string)) (string, error) {
		dir := t.TempDir()
		setup(dir)
		cmd := exec.Command(os.Args[0], "-test.run=^TestPluginScanner_Integration$", "-test.v")
		cmd.Env = []string{"PATH=" + dir, "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	output, err := run(func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "defenseclaw"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || strings.Contains(output, "--- SKIP") || !strings.Contains(output, "--- FAIL") {
		t.Fatalf("a defenseclaw on PATH without the execute bit must fail the integration test, err=%v:\n%s", err, output)
	}
	output, err = run(func(string) {})
	if err != nil || !strings.Contains(output, "--- SKIP") || strings.Contains(output, "--- FAIL") {
		t.Fatalf("no defenseclaw on PATH must skip the integration test, err=%v:\n%s", err, output)
	}
	// An empty PATH element names the current directory, which LookPath
	// searches like any other entry.
	here := t.TempDir()
	if err := os.WriteFile(filepath.Join(here, "defenseclaw"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPluginScanner_Integration$", "-test.v")
	cmd.Dir = here
	cmd.Env = []string{"PATH=" + string(os.PathListSeparator) + t.TempDir(), "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	combined, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(combined), "--- SKIP") || !strings.Contains(string(combined), "--- FAIL") {
		t.Fatalf("a defenseclaw without the execute bit in the directory an empty PATH element names must fail the integration test, err=%v:\n%s", err, combined)
	}
}

func TestResolvePluginCLIKeepsExplicitChoicesStrict(t *testing.T) {
	t.Setenv("DEFENSECLAW_BIN", "/explicit/defenseclaw")
	if binary, strict := resolvePluginCLI(); binary != "/explicit/defenseclaw" || !strict {
		t.Fatalf("explicit DEFENSECLAW_BIN = (%q, %v), want strict", binary, strict)
	}
}

// TestPluginScannerIntegrationFailsForAMissingExplicitCLI runs the integration
// test itself with DEFENSECLAW_BIN naming a file that is not there. An
// explicit choice is strict, so the test must fail, not skip.
func TestPluginScannerIntegrationFailsForAMissingExplicitCLI(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPluginScanner_Integration$", "-test.v")
	cmd.Env = append(os.Environ(), "DEFENSECLAW_BIN="+filepath.Join(t.TempDir(), "missing", "defenseclaw"))
	output, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(output), "--- SKIP") || !strings.Contains(string(output), "--- FAIL") {
		t.Fatalf("a missing explicit DEFENSECLAW_BIN must fail the integration test, err=%v:\n%s", err, output)
	}
}

// TestPluginScanner_Integration calls the real Python CLI and verifies
// Go can parse its output end-to-end. Skipped if defenseclaw is not installed.
func TestPluginScanner_Integration(t *testing.T) {
	binary, strict := resolvePluginCLI()
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

	t.Run("vendor identity can be disabled for the existing scan path", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "defenseclaw", DisableVendorIdentity: true}
		_, args := s.pluginScanCommand("/tmp/plugin")
		want := []string{"plugin", "scan", "--json", "/tmp/plugin", "--disable-vendor-identity"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("args = %v, want %v", args, want)
		}
	})

	t.Run("custom scanner arguments stay unchanged", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "/tmp/custom-scanner", DisableVendorIdentity: true}
		_, args := s.pluginScanCommand("/tmp/plugin")
		want := []string{"plugin", "scan", "--json", "/tmp/plugin"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("args = %v, want %v", args, want)
		}
	})
}
