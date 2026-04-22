// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLogActivityRoundTrip_CreateMutateDelete(t *testing.T) {
	l := newTestLogger(t)
	base := "resource/x"
	steps := []struct {
		action Action
		before map[string]any
		after  map[string]any
		diff   []ActivityDiffEntry
	}{
		{ActionConfigUpdate, nil, map[string]any{"k": "v"}, []ActivityDiffEntry{{Path: "k", Op: "add", After: "v"}}},
		{ActionConfigUpdate, map[string]any{"k": "v"}, map[string]any{"k": "v2"}, []ActivityDiffEntry{{Path: "k", Op: "replace", Before: "v", After: "v2"}}},
		{ActionConfigUpdate, map[string]any{"k": "v2"}, nil, []ActivityDiffEntry{{Path: "k", Op: "remove", Before: "v2"}}},
	}
	for i, step := range steps {
		if err := l.LogActivity(ActivityInput{
			Actor:       "t",
			Action:      step.action,
			TargetType:  "config",
			TargetID:    base,
			Before:      step.before,
			After:       step.after,
			Diff:        step.diff,
			VersionFrom: strings.Repeat("a", i+1),
			VersionTo:   strings.Repeat("b", i+1),
		}); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	rows, err := l.store.ListActivityEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("activity rows=%d want 3", len(rows))
	}
	for _, row := range rows {
		if row.DiffJSON == "" {
			t.Errorf("empty diff for id=%s", row.ID)
		}
		var raw []json.RawMessage
		if err := json.Unmarshal([]byte(row.DiffJSON), &raw); err != nil {
			t.Errorf("diff_json: %v", err)
		}
	}
}

func TestExportJSONLActivityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	s, err := NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := range 10 {
		id := fmt.Sprintf("%08d-%04d", i, i)
		if err := s.InsertActivityEvent(ActivityEventRow{
			ID:         uuid.New().String(),
			Timestamp:  now,
			Actor:      "a",
			Action:     "config-update",
			TargetType: "t",
			TargetID:   id,
			BeforeJSON: `{"n":` + fmt.Sprintf("%d", i) + `}`,
			AfterJSON:  `{"n":` + fmt.Sprintf("%d", i+1) + `}`,
			DiffJSON:   `[{"path":"n","op":"replace"}]`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out.jsonl")
	if err := s.ExportJSONL(out, 100, ExportJSONLOptions{IncludeActivity: true}); err != nil {
		t.Fatal(err)
	}
	actPath := strings.TrimSuffix(out, filepath.Ext(out)) + ".activity.jsonl"
	b, err := os.ReadFile(actPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 10 {
		t.Fatalf("activity lines=%d want 10", len(lines))
	}
	var first ActivityEventRow
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.BeforeJSON == "" || first.AfterJSON == "" || first.DiffJSON == "" {
		t.Fatalf("missing json fields: %+v", first)
	}
}
