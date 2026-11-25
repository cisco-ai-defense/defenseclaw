// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// kiroBootTree is every path under root with its kind and, for a file, its
// bytes: what a boot that does nothing leaves unchanged.
func kiroBootTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			tree[path] = entry.Type().String()
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		tree[path] = string(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return tree
}

// bootReclaimOf runs the boot reclaim of the data folder dataDir, which
// guards only OpenClaw, and returns what it wrote to stderr.
func bootReclaimOf(t *testing.T, dataDir, workspace string) string {
	t.Helper()
	return bootReclaimDuring(t, dataDir, workspace, nil)
}

// reclaimLogLine is a line the boot reclaim itself writes: every one of its
// messages starts "[guardrail] connector <name>" or "[guardrail] WARNING:
// connector <name>" (sidecar_unrostered_hooks.go).
var reclaimLogLine = regexp.MustCompile(`^\[guardrail\] (WARNING: )?connector [a-z0-9_-]+ `)

// bootReclaimDuring is bootReclaimOf with alongside run while the reclaim
// is captured. The stderr tee is process-wide, so a line another test's
// teardown still writes in that window ("[guardrail] removed connector devin
// teardown verified clean", seen in a full-package run) is in the capture
// too; only the reclaim's own lines are returned (rel-1-0-10:GAP-1772).
func bootReclaimDuring(t *testing.T, dataDir, workspace string, alongside func()) string {
	t.Helper()
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	cfg.Claw.WorkspaceDir = workspace
	s := &Sidecar{cfg: cfg}
	out := captureStderr(t, func() {
		if alongside != nil {
			alongside()
		}
		s.reclaimUnguardedConnectorHooks(context.Background(), connector.NewDefaultRegistry())
	})
	var own strings.Builder
	for _, line := range strings.SplitAfter(out, "\n") {
		if reclaimLogLine.MatchString(line) {
			own.WriteString(line)
		}
	}
	return own.String()
}

// Another test's teardown line in the capture window is not the boot
// reclaim's output: a boot with no Kiro residue still logs nothing
// (rel-1-0-10:GAP-1772).
func TestBootReclaimOutputIgnoresAnotherTestsTeardownLine(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataC := filepath.Join(home, "c", ".defenseclaw")
	if err := os.MkdirAll(dataC, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := func() {
		fmt.Fprintf(os.Stderr, "[guardrail] removed connector devin teardown verified clean\n")
	}
	if out := bootReclaimDuring(t, dataC, "", foreign); out != "" {
		t.Errorf("a boot with no Kiro residue was charged with another test's line: %q", out)
	}
	if !strings.Contains(captureStderr(t, foreign), "devin teardown") {
		t.Error("the capture no longer sees a line written during it; the check above proves nothing")
	}
}

// Review round 5 P2 of rel-1-0-10 GAP-1092/GAP-1174: the boot reclaim started
// only when VerifyClean, which read the files the current settings name,
// reported DefenseClaw hooks left. Residue only a backup record names (the
// workspace file B wrote before claw.workspace_dir changed, which an earlier
// build's reclaim skipped) never started it, so B's entries stayed there
// until a manual prune. The boot now cleans them, drops B's records, and the
// boot after it does nothing and says nothing.
func TestBootReclaimRunsWhenOnlyARecordNamesTheKiroResidue(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataB := filepath.Join(home, "b", ".defenseclaw")
	w1 := filepath.Join(home, "w1")
	w2 := filepath.Join(home, "w2")
	for _, dir := range []string{dataB, w1, w2} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	opts := connector.SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: w1}
	if err := connector.NewKiroConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	kiro := filepath.Join(home, ".kiro")
	for _, path := range []string{
		filepath.Join(kiro, "hooks", "defenseclaw.json"),
		filepath.Join(kiro, "agents", "defenseclaw.json"),
		filepath.Join(kiro, "settings", "cli.json"),
	} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	w1Hooks := filepath.Join(w1, ".kiro", "hooks", "defenseclaw.json")
	if data, err := os.ReadFile(w1Hooks); err != nil || !strings.Contains(string(data), dataB) {
		t.Fatalf("the W1 hook file is not install B's: %v", err)
	}

	out := bootReclaimOf(t, dataB, w2)
	if data, err := os.ReadFile(w1Hooks); err == nil && strings.Contains(string(data), dataB) {
		t.Errorf("install B's hooks stayed in the workspace file only its record names:\n%s", data)
	}
	records, err := os.ReadDir(filepath.Join(dataB, "connector_backups", "kiro"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, record := range records {
		t.Errorf("the boot reclaim kept the Kiro record %s", record.Name())
	}
	if !strings.Contains(out, "connector kiro") {
		t.Errorf("the boot reclaim did not say what it removed: %q", out)
	}

	before := kiroBootTree(t, home)
	if out := bootReclaimOf(t, dataB, w2); out != "" {
		t.Errorf("the boot after the reclaim logged %q", out)
	}
	assertKiroBootTreeUnchanged(t, before, kiroBootTree(t, home))
}

// A data folder with no Kiro residue and no Kiro record: its boot does no
// work and logs nothing.
func TestBootReclaimWithNoKiroResidueDoesNothing(t *testing.T) {
	home := t.TempDir()
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataC := filepath.Join(home, "c", ".defenseclaw")
	if err := os.MkdirAll(dataC, 0o700); err != nil {
		t.Fatal(err)
	}
	before := kiroBootTree(t, home)
	if out := bootReclaimOf(t, dataC, ""); out != "" {
		t.Errorf("a boot with no Kiro residue logged %q", out)
	}
	assertKiroBootTreeUnchanged(t, before, kiroBootTree(t, home))
}

func assertKiroBootTreeUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	for path, want := range before {
		if got, ok := after[path]; !ok {
			t.Errorf("the boot removed %s", path)
		} else if got != want {
			t.Errorf("the boot changed %s", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("the boot wrote %s", path)
		}
	}
}
