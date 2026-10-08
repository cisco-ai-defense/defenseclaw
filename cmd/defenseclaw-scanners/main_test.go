// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// GAP-0132: the runtime unpacker refuses entries that would leave its folder.
func TestUnpackRefusesEscapingEntries(t *testing.T) {
	for _, name := range []string{"../evil.py", "/abs.py", `python\..\..\x.py`, "a/../../b.py"} {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, _ := w.Create(name)
		_, _ = f.Write([]byte("x"))
		_ = w.Close()
		if err := unpack(buf.Bytes(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "relative path") {
			t.Fatalf("unpack(%q) = %v, want refusal", name, err)
		}
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("python/Lib/site-packages/ok.py")
	_, _ = f.Write([]byte("ok"))
	_ = w.Close()
	if err := unpack(buf.Bytes(), t.TempDir()); err != nil {
		t.Fatalf("unpack of a plain entry: %v", err)
	}
}

// A folder that carries the public completion marker is not trusted:
// prepare compares every archived file with the embedded archive.
func TestVerifyRuntimeRejectsAChangedFile(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("python/python.exe")
	_, _ = f.Write([]byte("genuine"))
	_ = w.Close()
	dir := t.TempDir()
	if err := unpack(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntime(dir, buf.Bytes()); err != nil {
		t.Fatalf("verify an untouched tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "python", "python.exe"), []byte("planted!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntime(dir, buf.Bytes()); err == nil {
		t.Fatal("a changed python.exe verified")
	}
}

// GAP-0262: a half-removed runtime folder must not block the next prepare. The
// removal is retried (a file held open for a moment), and a folder that still
// stays is moved aside rather than left in the way.
func TestClearRuntimeDirRetriesThenMovesAside(t *testing.T) {
	realRemove, attempts, delay := removeAll, clearRuntimeAttempts, clearRuntimeDelay
	defer func() { removeAll, clearRuntimeAttempts, clearRuntimeDelay = realRemove, attempts, delay }()
	clearRuntimeAttempts, clearRuntimeDelay = 3, time.Millisecond

	root := t.TempDir()
	dir := filepath.Join(root, "b9c42dbc62f16be3")
	if err := os.MkdirAll(filepath.Join(dir, "python"), 0o755); err != nil {
		t.Fatal(err)
	}
	failures := 0
	removeAll = func(path string) error {
		if failures++; failures < 3 {
			return &os.PathError{Op: "unlinkat", Path: filepath.Join(path, "python", "x.pyd"), Err: errors.New("Access is denied")}
		}
		return realRemove(path)
	}
	if err := clearRuntimeDir(dir); err != nil || failures != 3 {
		t.Fatalf("clearRuntimeDir after two failures = %v (attempts %d)", err, failures)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the folder is still there: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "python"), 0o755); err != nil {
		t.Fatal(err)
	}
	removeAll = func(path string) error {
		return &os.PathError{Op: "unlinkat", Path: filepath.Join(path, "python", "x.pyd"), Err: errors.New("Access is denied")}
	}
	if err := clearRuntimeDir(dir); err != nil {
		t.Fatalf("a folder that cannot be removed is moved aside: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the blocked folder is still at its name: %v", err)
	}
	stale, _ := filepath.Glob(filepath.Join(root, ".stale-*"))
	if len(stale) != 1 {
		t.Fatalf("expected one .stale-* folder, got %v", stale)
	}
	pruneOtherRuntimes(root, "keep")
	if left, _ := filepath.Glob(filepath.Join(root, ".stale-*")); len(left) != 0 {
		t.Fatalf("prune left the moved-aside folder: %v", left)
	}
}

// The embedded Windows plugin entry point must carry configured rule-pack
// findings into the JSON consumed by the Go scanner.
func TestPluginRuntimeAppliesRulePackOverlay(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	const stubs = `import sys,types
for name in ("defenseclaw", "defenseclaw.config", "defenseclaw.scanner",
             "defenseclaw.scanner.plugin_scanner", "defenseclaw.scanner.plugin_scanner.types",
             "defenseclaw.scanner.plugin_scanner.self_identity", "defenseclaw.scanner.rulepack"):
    sys.modules[name]=types.ModuleType(name)
class Options:
    include_self=False
    trusted_self_paths=()
class Result:
    def to_dict(self):
        return {"scanner":"plugin-scanner","target":"/plugin","timestamp":"2026-01-01T00:00:00Z","findings":[]}
class Finding:
    id="PACK-MARKER"
    location="plugin.py:1"
    line_number=1
    def to_dict(self):
        return {"id":self.id,"location":self.location,"severity":"HIGH","title":"Marker","scanner":"rule-pack","tags":[],"line_number":self.line_number}
sys.modules["defenseclaw.scanner.plugin_scanner"].scan_plugin=lambda target,options: Result()
sys.modules["defenseclaw.scanner.plugin_scanner.types"].PluginScanOptions=Options
sys.modules["defenseclaw.scanner.plugin_scanner.self_identity"].is_first_party_self_target=lambda target,**kw: False
sys.modules["defenseclaw.config"].load=lambda: object()
sys.modules["defenseclaw.scanner.rulepack"].overlay_findings=lambda cfg,connector=None,**kw: [Finding()] if connector=="codex" else []
`
	cmd := exec.Command(python, "-c", stubs+"\n"+pluginScanScript, "/plugin", "--connector", "codex")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("plugin runtime script: %v: %s", err, output)
	}
	var result struct {
		Findings []struct {
			ID      string   `json:"id"`
			Scanner string   `json:"scanner"`
			Line    int      `json:"line"`
			Tags    []string `json:"tags"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("plugin runtime output: %v: %s", err, output)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "PACK-MARKER" ||
		result.Findings[0].Scanner != "plugin-scanner" || result.Findings[0].Line != 1 ||
		!slices.Contains(result.Findings[0].Tags, "analyzer:rule-pack") {
		t.Fatalf("rule-pack finding missing: %s", output)
	}
}
