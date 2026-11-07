// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func d1ReadTSV(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(strings.ReplaceAll(string(data), "\t", "|"))
}

// A cell that outlives its limit ends the run cleanly with the row recorded
// as timeout and a marker; a resumed run continues after that row and the two
// runs together give one complete verdict file (rel-1-0-6 GAP-0607 review 7).
func TestD1PrivateReplayStopsAfterATimedOutRowAndResumes(t *testing.T) {
	rows := d1ReadRows(t, "testdata/d1-shapes.jsonl")[:3]
	output := filepath.Join(t.TempDir(), "verdicts.tsv")

	t.Setenv("DC_D1_CELL_TIMEOUT", "1ns")
	run, err := d1StartRun(output, false)
	if err != nil {
		t.Fatal(err)
	}
	if !d1Replay(t, rows, run) {
		t.Fatal("a timed-out row must stop the run")
	}
	run.Output.Close()
	marker, err := os.ReadFile(output + ".stalled")
	if err != nil || strings.TrimSpace(string(marker)) != rows[0].ID {
		t.Fatalf("stall marker = %q, %v; want the first row", marker, err)
	}
	first := d1ReadTSV(t, output)
	if len(first) != 4 {
		t.Fatalf("first run recorded %d cells, want the 4 cells of one row", len(first))
	}
	for _, line := range first {
		if !strings.HasPrefix(line, rows[0].ID+"|") || !strings.Contains(line, "|timeout|") {
			t.Fatalf("first run cell %q is not a timeout of the stalled row", line)
		}
	}

	t.Setenv("DC_D1_CELL_TIMEOUT", "1m")
	resumed, err := d1StartRun(output, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, stale := os.Stat(output + ".stalled"); !os.IsNotExist(stale) {
		t.Fatal("a new run must clear the stale stall marker")
	}
	if !resumed.Done[rows[0].ID] || len(resumed.Done) != 1 {
		t.Fatalf("resume keeps %v, want only the recorded row", resumed.Done)
	}
	if d1Replay(t, rows, resumed) {
		t.Fatal("the resumed run must finish")
	}
	resumed.Output.Close()
	cells := make(map[string]bool)
	for _, line := range d1ReadTSV(t, output) {
		parts := strings.Split(line, "|")
		key := parts[0] + " " + parts[1]
		if cells[key] {
			t.Fatalf("cell %s recorded twice", key)
		}
		cells[key] = true
	}
	if len(cells) != 12 {
		t.Fatalf("resumed output has %d cells, want 3 rows x 4", len(cells))
	}
}

func TestD1StartRunResumeDropsPartialRows(t *testing.T) {
	output := filepath.Join(t.TempDir(), "verdicts.tsv")
	content := "a\tcodex/oss\tallow\t-\na\tcodex/managed-balanced\tallow\t-\n" +
		"a\tclaudecode/oss\tallow\t-\na\tclaudecode/managed-balanced\talert\tR\n" +
		"b\tcodex/oss\tallow\t-\nb\tcodex/managed-balanced\tallow\t-\nb\tclaudecode/o"
	if err := os.WriteFile(output, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := d1StartRun(output, true)
	if err != nil {
		t.Fatal(err)
	}
	run.Output.Close()
	if len(run.Done) != 1 || !run.Done["a"] {
		t.Fatalf("resume keeps %v, want only the complete row", run.Done)
	}
	if got := len(d1ReadTSV(t, output)); got != 4 {
		t.Fatalf("resumed file keeps %d cells, want the 4 of the complete row", got)
	}
	fresh, err := d1StartRun(output, false)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Output.Close()
	if len(fresh.Done) != 0 || len(d1ReadTSV(t, output)) != 0 {
		t.Fatal("a run without resume starts the file anew")
	}
}
