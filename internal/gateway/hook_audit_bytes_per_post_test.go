// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestHookAuditBytesPerPost measures what one Claude Code hook post adds to
// the audit store (substrate-1:GAP-0570): the real hook handler, v8 runtime
// and audit store on disk, PreToolUse+PostToolUse pairs of Bash and Read
// calls over several sessions, and the store's used pages, file sizes and
// rows before and after. It logs HOOKBYTES lines and asserts only that the
// posts wrote something; the size cap's retention cadence is sized from these
// numbers (internal/observability/runtime RetentionSizeCapCheckInterval).
// DEFENSECLAW_HOOK_BYTES_PAIRS sets the pair count (default 300).
func TestHookAuditBytesPerPost(t *testing.T) {
	pairs := 300
	if raw := os.Getenv("DEFENSECLAW_HOOK_BYTES_PAIRS"); raw != "" {
		if _, err := fmt.Sscan(raw, &pairs); err != nil || pairs < 1 {
			t.Fatalf("DEFENSECLAW_HOOK_BYTES_PAIRS=%q is not a count", raw)
		}
	}
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()
	stdout := strings.Repeat("drwxr-xr-x  2 dev dev 4096 Nov 17 12:00 src\n", 24)
	content := strings.Repeat("func handler(w http.ResponseWriter, r *http.Request) {}\n", 36)

	post := func(payload map[string]any) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("hook post answered %d: %s", recorder.Code, recorder.Body.String())
		}
	}
	pair := func(index int) {
		session := fmt.Sprintf("hook-bytes-session-%02d", index%10)
		base := map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, session+".jsonl"), "cwd": cwd,
			"permission_mode": "default", "tool_use_id": fmt.Sprintf("toolu_%024d", index),
		}
		with := func(extra map[string]any) map[string]any {
			out := make(map[string]any, len(base)+len(extra))
			for key, value := range base {
				out[key] = value
			}
			for key, value := range extra {
				out[key] = value
			}
			return out
		}
		if index%2 == 0 {
			input := map[string]any{"command": fmt.Sprintf("ls -la src/pkg%d && git status --short", index), "description": "List the package"}
			post(with(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": input}))
			post(with(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": input,
				"tool_response": map[string]any{"stdout": stdout, "stderr": "", "interrupted": false, "isImage": false}}))
			return
		}
		file := filepath.Join(cwd, fmt.Sprintf("handler%d.go", index))
		input := map[string]any{"file_path": file}
		post(with(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": input}))
		post(with(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": input,
			"tool_response": map[string]any{"type": "text", "file": map[string]any{
				"filePath": file, "content": content, "numLines": 36, "startLine": 1, "totalLines": 36,
			}}}))
	}

	db, err := sql.Open("sqlite", fixture.path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	type sample struct{ used, files, rows, auditRows int64 }
	measure := func() sample {
		t.Helper()
		var s sample
		var pages, free, size int64
		if err := db.QueryRow(`SELECT (SELECT page_count FROM pragma_page_count()),
			(SELECT freelist_count FROM pragma_freelist_count()),
			(SELECT page_size FROM pragma_page_size())`).Scan(&pages, &free, &size); err != nil {
			t.Fatal(err)
		}
		s.used = (pages - free) * size
		entries, err := os.ReadDir(filepath.Dir(fixture.path))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
				s.files += info.Size()
			}
		}
		rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
		if err != nil {
			t.Fatal(err)
		}
		var tables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			tables = append(tables, name)
		}
		_ = rows.Close()
		for _, table := range tables {
			var count int64
			if err := db.QueryRow(`SELECT COUNT(*) FROM "` + table + `"`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			s.rows += count
			if table == "audit_events" {
				s.auditRows = count
			}
		}
		return s
	}
	settled := func() sample {
		t.Helper()
		last := measure()
		for range 50 {
			time.Sleep(200 * time.Millisecond)
			next := measure()
			if next == last {
				return next
			}
			last = next
		}
		return last
	}

	// Warm up: schema pages, first-session state and caches are not per post.
	for index := range 20 {
		pair(1_000_000 + index)
	}
	before := settled()
	began := time.Now()
	for index := range pairs {
		pair(index)
	}
	elapsed := time.Since(began)
	after := settled()
	posts := int64(2 * pairs)
	if after.used <= before.used || after.rows <= before.rows {
		t.Fatalf("hook posts wrote nothing: before %+v after %+v", before, after)
	}
	usedPerPost := (after.used - before.used) / posts
	t.Logf("HOOKBYTES posts=%d in %v: used pages +%d B (%d B/post), files +%d B (%d B/post incl. WAL), rows +%d (%.2f/post), audit_events +%d (%.2f/post)",
		posts, elapsed.Round(time.Millisecond), after.used-before.used, usedPerPost,
		after.files-before.files, (after.files-before.files)/posts,
		after.rows-before.rows, float64(after.rows-before.rows)/float64(posts),
		after.auditRows-before.auditRows, float64(after.auditRows-before.auditRows)/float64(posts))
	for _, rate := range []int64{50, 60} {
		t.Logf("HOOKBYTES at %d posts/s per replica: %.0f MiB/hour of used pages", rate,
			float64(usedPerPost*rate*3600)/float64(1<<20))
	}
}
