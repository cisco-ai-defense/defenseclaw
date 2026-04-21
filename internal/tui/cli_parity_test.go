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

package tui

// CLI ↔ TUI parity test.
//
// The TUI maps user actions to CLI invocations through BuildRegistry().
// Every entry there must point at a real `defenseclaw` (or
// `defenseclaw-gateway`) subcommand and pass real, recognized flags.
//
// We enforce that contract here using `scripts/audit_parity.py`, which
// walks the Click tree at import time and emits a JSON manifest of
// every subcommand and its accepted options. This test:
//
//   1. Locates the script + a Python interpreter.
//   2. Loads the JSON manifest into in-memory lookup tables.
//   3. For each `defenseclaw` entry in BuildRegistry(), splits
//      CLIArgs into a path prefix + flags, then asserts both the path
//      and every flag are present in the manifest.
//   4. Reports a clear "no such command" / "no such flag" for any
//      mismatch — the failure message names the offending TUI entry so
//      operators can fix the registry without grepping JSON.
//
// `defenseclaw-gateway` entries are skipped here on purpose: the
// gateway is a Cobra app whose tree we'd have to introspect via a
// separate Go-side helper. They're covered by the dedicated
// `e2e/gateway_command_help_test.sh` shell suite.
//
// The test is auto-skipped (not failed) when:
//   - `python3`/`uv` isn't available on PATH
//   - the audit script can't import `defenseclaw` (CI hasn't run
//     `pip install -e .` yet)
// CI runs after `make pycli` so the skip is essentially never hit
// in production pipelines.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// parityCommand mirrors the schema emitted by scripts/audit_parity.py.
// We only deserialize the fields we actually consult, so additive
// changes to the script (new keys) won't break the test.
type parityCommand struct {
	Path    []string `json:"path"`
	Options []string `json:"options"`
	IsGroup bool     `json:"is_group"`
}

type parityManifest struct {
	Binary   string          `json:"binary"`
	Commands []parityCommand `json:"commands"`
}

// projectRoot walks up from the current test file's directory until
// it finds the repo root (anchored by go.mod). Used so the test
// works regardless of where `go test` was invoked from.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate project root")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod walking up from %s", file)
	return ""
}

// findPythonRunner picks the highest-fidelity way to run a script
// against the project's pinned Python deps. We prefer `uv run python`
// since the repo is uv-managed (uv.lock is committed), and fall back
// to a system `python3` only if uv is unavailable. Returns nil if
// neither is on PATH so the test can skip cleanly.
func findPythonRunner(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("uv"); err == nil {
		return []string{"uv", "run", "python"}
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return []string{p}
	}
	if p, err := exec.LookPath("python"); err == nil {
		return []string{p}
	}
	return nil
}

// loadManifest runs scripts/audit_parity.py and parses the resulting
// JSON. Returns (nil, "skip-reason") when the runner exits non-zero
// for any environmental reason (missing deps, missing module). Real
// JSON-parse errors still bubble up as test failures so a malformed
// manifest is loud instead of silently passing.
func loadManifest(t *testing.T) (*parityManifest, string) {
	t.Helper()
	root := projectRoot(t)
	runner := findPythonRunner(t)
	if runner == nil {
		return nil, "no Python interpreter on PATH"
	}
	args := append(append([]string{}, runner[1:]...), filepath.Join(root, "scripts", "audit_parity.py"))
	cmd := exec.Command(runner[0], args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		// Soft-skip on environmental failures so the parity test
		// stays useful in dev shells where the venv hasn't been
		// hydrated yet. CI gates this with a real `make pycli` step.
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		return nil, "audit_parity.py failed: " + err.Error() + "\nstderr:\n" + stderr
	}
	var manifest parityManifest
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("audit_parity.py emitted invalid JSON: %v\nfirst 200 bytes: %q", err, string(out[:min(200, len(out))]))
	}
	if len(manifest.Commands) == 0 {
		t.Fatal("audit_parity.py emitted an empty command list — the manifest is broken")
	}
	return &manifest, ""
}

// indexManifest builds two lookup tables from the raw manifest:
//
//   - byPath: "skill scan" -> *parityCommand (fast existence + flag check)
//   - allPaths: ordered list for diagnostics on the failure side
//
// We store options in a set for O(1) membership.
func indexManifest(m *parityManifest) (map[string]*parityCommand, map[string]map[string]struct{}) {
	byPath := make(map[string]*parityCommand, len(m.Commands))
	flagSets := make(map[string]map[string]struct{}, len(m.Commands))
	for i := range m.Commands {
		c := &m.Commands[i]
		key := strings.Join(c.Path, " ")
		byPath[key] = c
		flags := make(map[string]struct{}, len(c.Options)+2)
		for _, o := range c.Options {
			flags[o] = struct{}{}
		}
		// Click and Cobra both implicitly accept --help on every
		// command/group, but the manifest doesn't list it because
		// it's not a click.Option. Add it so registry entries that
		// shell out `defenseclaw --help` (the "help" alias) pass.
		flags["--help"] = struct{}{}
		flags["-h"] = struct{}{}
		flagSets[key] = flags
	}
	return byPath, flagSets
}

// splitArgs separates a CLIArgs slice into its command path (leading
// non-flag tokens) and the trailing flags. Stops the path at the
// first token that begins with "-". Tokens after a flag (typically
// flag values) are not flags themselves and are folded into the
// returned values list — but we don't validate values, only the
// flag names.
func splitArgs(args []string) (path []string, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = args[i:]
			return path, flags
		}
		path = append(path, a)
	}
	return path, nil
}

// flagNames extracts only the flag tokens (strings starting with "-")
// from a slice that may contain interleaved values. e.g.
// ["--limit", "10", "-y"] -> ["--limit", "-y"].
func flagNames(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if strings.HasPrefix(t, "-") {
			// Click/Cobra both accept --flag=value; strip the value
			// portion for the membership lookup.
			if idx := strings.Index(t, "="); idx > 0 {
				t = t[:idx]
			}
			out = append(out, t)
		}
	}
	return out
}

func TestBuildRegistryParity(t *testing.T) {
	manifest, skipReason := loadManifest(t)
	if skipReason != "" {
		t.Skip(skipReason)
	}
	byPath, flagSets := indexManifest(manifest)

	registry := BuildRegistry()
	if len(registry) == 0 {
		t.Fatal("BuildRegistry() returned no entries — TUI/CLI parity cannot be verified")
	}

	var (
		checked  int
		skipped  int
		failures []string
	)

	for _, entry := range registry {
		// Gateway entries are validated separately (see file-level
		// comment). We still want to count them so a future drop
		// in registry size is visible in test output.
		if entry.CLIBinary != "defenseclaw" {
			skipped++
			continue
		}
		checked++

		path, flags := splitArgs(entry.CLIArgs)
		// The root group itself ("defenseclaw --help") has an empty
		// path. That's a legitimate manifest entry too.
		key := strings.Join(path, " ")
		cmd, ok := byPath[key]
		if !ok {
			failures = append(failures, fmt.Sprintf(
				"TUI %q -> CLI path %q does not exist (binary=%s, args=%v)",
				entry.TUIName, key, entry.CLIBinary, entry.CLIArgs))
			continue
		}

		// We allow the TUI to invoke an intermediate group (e.g.
		// `defenseclaw policy edit`) so long as the CLI exposes it
		// — Click prints a help screen, which is fine UX. The
		// existing entries don't actually do this, but the
		// invariant is harmless to allow.
		_ = cmd

		recognized := flagSets[key]
		for _, flag := range flagNames(flags) {
			if _, ok := recognized[flag]; !ok {
				failures = append(failures, fmt.Sprintf(
					"TUI %q passes flag %q to %q but the CLI does not accept it (recognized: %v)",
					entry.TUIName, flag, "defenseclaw "+key, sortedKeys(recognized)))
			}
		}
	}

	t.Logf("validated %d defenseclaw entries; %d gateway entries skipped (covered by e2e shell tests)", checked, skipped)

	if len(failures) > 0 {
		t.Fatalf("CLI parity check failed (%d issues):\n  - %s",
			len(failures), strings.Join(failures, "\n  - "))
	}
}

// sortedKeys returns a deterministic slice for failure messages —
// otherwise Go's map iteration order would make the test output
// non-deterministic and hard to bisect.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestAuditParityScriptShape sanity-checks the manifest itself: it
// has the `defenseclaw` binary tag, every command has a non-nil
// path slice (root may be empty but must exist), and the well-known
// commands the TUI relies on are present. This is a smoke test for
// the script's contract — if someone changes the JSON shape the
// failure message points at the script, not at a downstream
// consumer.
func TestAuditParityScriptShape(t *testing.T) {
	manifest, skipReason := loadManifest(t)
	if skipReason != "" {
		t.Skip(skipReason)
	}
	if manifest.Binary != "defenseclaw" {
		t.Errorf("manifest.binary = %q, want %q", manifest.Binary, "defenseclaw")
	}

	wantedPaths := []string{
		"",                                   // root group
		"skill scan",                         // primary scan path
		"mcp set",                            // primary install path
		"policy edit actions",                // deeply-nested edit
		"setup observability migrate-splunk", // long-tail setup
		"doctor",                             // overview cache feed
		"aibom scan",                         // inventory feed
	}
	byPath, _ := indexManifest(manifest)
	for _, want := range wantedPaths {
		if _, ok := byPath[want]; !ok {
			t.Errorf("manifest missing well-known command path %q", want)
		}
	}
}
