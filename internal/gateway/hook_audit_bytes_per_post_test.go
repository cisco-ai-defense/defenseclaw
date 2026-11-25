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

// hookLoad drives the real Claude Code hook handler, v8 runtime and audit
// store on disk with PreToolUse+PostToolUse pairs of Bash and Read calls over
// ten sessions, the shape of the E5 J43 flood (substrate-1:GAP-0570).
type hookLoad struct {
	fixture sidecarRuntimeFixture
	api     *APIServer
	db      *sql.DB
	cwd     string
	stdout  string
	content string
}

func newHookLoad(t *testing.T) *hookLoad {
	t.Helper()
	installCorrelationHMACForTest(t)
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
	db, err := sql.Open("sqlite", fixture.path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	return &hookLoad{
		fixture: fixture, api: api, db: db, cwd: t.TempDir(),
		stdout:  strings.Repeat("drwxr-xr-x  2 dev dev 4096 Nov 17 12:00 src\n", 24),
		content: strings.Repeat("func handler(w http.ResponseWriter, r *http.Request) {}\n", 36),
	}
}

func (l *hookLoad) post(t *testing.T, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	l.api.handleAgentHook("claudecode").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("hook post answered %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "internal error") {
		t.Fatalf("hook post failed inside the gateway: %s", recorder.Body.String())
	}
}

// pair posts one PreToolUse and its PostToolUse.
func (l *hookLoad) pair(t *testing.T, index int) {
	t.Helper()
	session := fmt.Sprintf("hook-bytes-session-%02d", index%10)
	base := map[string]any{
		"session_id": session, "transcript_path": filepath.Join(l.cwd, session+".jsonl"), "cwd": l.cwd,
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
		l.post(t, with(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": input}))
		l.post(t, with(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": input,
			"tool_response": map[string]any{"stdout": l.stdout, "stderr": "", "interrupted": false, "isImage": false}}))
		return
	}
	file := filepath.Join(l.cwd, fmt.Sprintf("handler%d.go", index))
	input := map[string]any{"file_path": file}
	l.post(t, with(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": input}))
	l.post(t, with(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": input,
		"tool_response": map[string]any{"type": "text", "file": map[string]any{
			"filePath": file, "content": l.content, "numLines": 36, "startLine": 1, "totalLines": 36,
		}}}))
}

type hookLoadSample struct{ used, files, rows, auditRows int64 }

func (l *hookLoad) usedBytes(t *testing.T) int64 {
	t.Helper()
	var pages, free, size int64
	if err := l.db.QueryRow(`SELECT (SELECT page_count FROM pragma_page_count()),
		(SELECT freelist_count FROM pragma_freelist_count()),
		(SELECT page_size FROM pragma_page_size())`).Scan(&pages, &free, &size); err != nil {
		t.Fatal(err)
	}
	return (pages - free) * size
}

func (l *hookLoad) measure(t *testing.T) hookLoadSample {
	t.Helper()
	s := hookLoadSample{used: l.usedBytes(t)}
	entries, err := os.ReadDir(filepath.Dir(l.fixture.path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
			s.files += info.Size()
		}
	}
	rows, err := l.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
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
		if err := l.db.QueryRow(`SELECT COUNT(*) FROM "` + table + `"`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		s.rows += count
		if table == "audit_events" {
			s.auditRows = count
		}
	}
	return s
}

// settled waits for the runtime's asynchronous writes to stop.
func (l *hookLoad) settled(t *testing.T) hookLoadSample {
	t.Helper()
	last := l.measure(t)
	for range 50 {
		time.Sleep(200 * time.Millisecond)
		next := l.measure(t)
		if next == last {
			return next
		}
		last = next
	}
	return last
}

// TestHookAuditBytesPerPost measures what one Claude Code hook post adds to
// the audit store (substrate-1:GAP-0570): the store's used pages, file sizes
// and rows before and after. It logs HOOKBYTES lines and asserts only that
// the posts wrote something; the size cap's check cadence is sized from these
// numbers (internal/observability/runtime RetentionSizeCapCheckInterval).
// Measured on dc-sub-gates (go1.26.4, 1000 pairs): 25501 B of used pages and
// 3 audit_events rows per post, so 50 posts a second are about 4.3 GiB an
// hour. The file sizes include the WAL, which this fixture never checkpoints
// (the gateway's WAL guard bounds it at audit.WALHardLimitBytes).
// DEFENSECLAW_HOOK_BYTES_PAIRS sets the pair count (default 150).
func TestHookAuditBytesPerPost(t *testing.T) {
	pairs := 150
	if raw := os.Getenv("DEFENSECLAW_HOOK_BYTES_PAIRS"); raw != "" {
		if _, err := fmt.Sscan(raw, &pairs); err != nil || pairs < 1 {
			t.Fatalf("DEFENSECLAW_HOOK_BYTES_PAIRS=%q is not a count", raw)
		}
	}
	load := newHookLoad(t)
	// Warm up: schema pages, first-session state and caches are not per post.
	for index := range 20 {
		load.pair(t, 1_000_000+index)
	}
	before := load.settled(t)
	began := time.Now()
	for index := range pairs {
		load.pair(t, index)
	}
	elapsed := time.Since(began)
	after := load.settled(t)
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

// substrate-1:GAP-0570: under the E5 flood a replica's store grew by about
// 4.3 GiB an hour, four times the chart's 1 GiB cap, and the cap never
// deleted the newest hour, so the store filled its volume and every hook
// failed with an internal error. Here real hook posts write about three times
// an 8 MiB cap, and a capped retention pass runs every 10
// pairs (about 0.5 MiB, a larger share of this cap than the 30-second check is of
// 1 GiB at 50 posts a second): the used pages must stay under the cap, every
// post must be answered, and every audit row a post wrote must have been
// written (rows kept plus rows the cap deleted).
func TestHookAuditStaysUnderTheSizeCapUnderHookLoad(t *testing.T) {
	const (
		capMiB = 8
		pairs  = 500
		every  = 10
	)
	load := newHookLoad(t)
	judge, err := audit.NewJudgeBodyStore(filepath.Join(filepath.Dir(load.fixture.path), "judge-cap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = judge.Close() })
	reaper, err := audit.NewRetentionReaper(load.fixture.store, judge, 7, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reaper.UpdateMaxStoreMB(capMiB); err != nil {
		t.Fatal(err)
	}
	capBytes := int64(capMiB) << 20
	for index := range 20 {
		load.pair(t, 1_000_000+index)
	}
	start := load.settled(t)
	var deleted, peak int64
	pass := func(at int) {
		t.Helper()
		for runs := 0; ; runs++ {
			result, err := reaper.Run(t.Context())
			if err != nil {
				class, cause := audit.RetentionFailureDetail(err)
				t.Fatalf("pair %d: retention pass failed (%s): %s", at, class, cause)
			}
			deleted += result.RowsDeleted[audit.RetentionAuditEvents]
			if !result.Backlog || runs >= 5 {
				break
			}
		}
		used := load.usedBytes(t)
		peak = max(peak, used)
		if used > capBytes {
			t.Fatalf("pair %d: the store uses %d bytes after the capped pass, cap %d (%d audit rows deleted so far)",
				at, used, capBytes, deleted)
		}
	}
	for index := range pairs {
		load.pair(t, index)
		if (index+1)%every == 0 {
			pass(index)
		}
	}
	end := load.settled(t)
	pass(pairs)
	posts := int64(2 * pairs)
	written := end.auditRows + deleted - start.auditRows
	if written != 3*posts {
		t.Fatalf("audit rows written %d (kept %d + deleted %d - %d before), want 3 per post = %d",
			written, end.auditRows, deleted, start.auditRows, 3*posts)
	}
	// Over three caps of rows went through: the cap deleted more than it kept.
	if deleted <= end.auditRows {
		t.Fatalf("the cap deleted %d audit rows and kept %d; the test does not load the store enough", deleted, end.auditRows)
	}
	if deleted == 0 {
		t.Fatal("the cap deleted nothing")
	}
	t.Logf("HOOKCAP cap %d MiB, %d posts: peak used %d bytes, %d audit rows deleted, %d kept", capMiB, posts, peak, deleted, end.auditRows)
}
