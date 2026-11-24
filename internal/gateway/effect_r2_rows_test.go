// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r2Row is one linux posix row of the DET111 program-table corpus
// (internal/effects/testdata/det111_r2.cases.jsonl), its /home/alice
// spellings moved to the test home.
type r2Row struct{ id, cmd, cwd string }

// det111R2Rows returns the rows of ids, in that order, read with home as the
// account home; a missing id fails the test.
func det111R2Rows(t *testing.T, home string, ids ...string) []r2Row {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "effects", "testdata", "det111_r2.cases.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	byID := map[string]r2Row{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var c struct {
			ID      string
			Payload struct {
				Args    map[string]any
				CWD     string
				Dialect string
			}
			Strata struct{ Platform string }
		}
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if c.Strata.Platform != "linux" || c.Payload.Dialect != "posix" {
			continue
		}
		cmd, _ := c.Payload.Args["command"].(string)
		cwd := strings.ReplaceAll(c.Payload.CWD, "/home/alice", home)
		if cwd == "" || !filepath.IsAbs(cwd) {
			cwd = filepath.Join(home, "proj")
		}
		byID[c.ID] = r2Row{id: c.ID, cmd: strings.ReplaceAll(cmd, "/home/alice", home), cwd: cwd}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	out := make([]r2Row, 0, len(ids))
	for _, id := range ids {
		row, ok := byID[id]
		if !ok {
			t.Fatalf("det111_r2 row %s is not in the corpus", id)
		}
		out = append(out, row)
	}
	return out
}

// r2Home is a test home with the protected members and project files the
// det111_r2 rows name, set as HOME.
func r2Home(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, name := range []string{".ssh/authorized_keys", ".ssh/id_rsa", ".aws/credentials", ".bashrc",
		".claude/settings.json", ".codex/hooks.json", ".defenseclaw/config.yaml",
		"proj/notes.txt", "proj/README.md", "proj/source.txt", "proj/out.txt"} {
		p := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home
}

// r2Action is the hook action of row on connector in api's tier.
func r2Action(api *APIServer, connector string, row r2Row) string {
	if connector == "codex" {
		return api.evaluateCodexHook(context.Background(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "shell", CWD: row.cwd,
			ToolInput: map[string]interface{}{"command": row.cmd},
		}).Action
	}
	return api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "det111-r2", ToolName: "Bash", CWD: row.cwd,
		ToolInput: map[string]interface{}{"command": row.cmd},
	}).Action
}

// r2Cells checks rows in the five tiers (boundedTestTiers names) and both
// connectors with the lane mode the build ships: want gives a row's action
// in a tier.
func r2Cells(t *testing.T, rows []r2Row, want func(id, tier string) string) {
	t.Helper()
	useDefaultLaneGeneration(t)
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				if got, w := r2Action(api, connector, row), want(row.id, tier.name); got != w {
					t.Errorf("%s %s %s: %s, want %s", tier.name, connector, row.id, got, w)
				}
			}
		}
	}
}

// r2Strict reports the strict and managed strict tiers.
func r2Strict(tier string) bool { return strings.Contains(tier, "strict") }
