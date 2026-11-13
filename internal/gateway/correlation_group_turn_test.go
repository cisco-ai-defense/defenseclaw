// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func setHookCorrelationGroupLimits(t *testing.T, limits audit.CorrelationGroupLimits) {
	t.Helper()
	previous := hookCorrelationGroupLimits
	hookCorrelationGroupLimits = limits
	t.Cleanup(func() { hookCorrelationGroupLimits = previous })
}

func setHookCorrelationGroupOccurrences(t *testing.T, occurrences int) {
	t.Helper()
	limits := hookCorrelationGroupLimits
	limits.Occurrences = occurrences
	setHookCorrelationGroupLimits(t, limits)
}

type groupHookCall struct{ session, event, tool string }

// groupIdentityCalls are two Claude Code sessions interleaved, in waves: a
// tool's PostToolUse comes in a wave after the one that answered its
// PreToolUse, as the agent sends it after the tool ran. Inside a wave a
// session has prompts, tool starts, tool ends out of order and stops.
func groupIdentityCalls() [][]groupHookCall {
	a, b := "s8-identity-a", "s8-identity-b"
	return [][]groupHookCall{
		{
			{a, "SessionStart", ""}, {b, "SessionStart", ""},
			{a, "UserPromptSubmit", ""}, {b, "UserPromptSubmit", ""},
			{a, "PreToolUse", "toolu_a1"}, {b, "PreToolUse", "toolu_b1"},
			{a, "PreToolUse", "toolu_a2"}, {a, "PreToolUse", "toolu_a3"},
		},
		{
			{a, "PostToolUse", "toolu_a1"}, {b, "PostToolUse", "toolu_b1"},
			{a, "PostToolUse", "toolu_a3"}, {b, "PreToolUse", "toolu_b2"},
			{a, "PostToolUse", "toolu_a2"}, {a, "UserPromptSubmit", ""},
			{a, "PreToolUse", "toolu_a4"},
		},
		{
			{b, "PostToolUse", "toolu_b2"}, {a, "PostToolUse", "toolu_a4"},
			{a, "Stop", ""}, {b, "Stop", ""},
		},
	}
}

func groupHookBody(t *testing.T, cwd string, call groupHookCall) []byte {
	t.Helper()
	body := map[string]any{"hook_event_name": call.event, "session_id": call.session, "cwd": cwd}
	switch call.event {
	case "SessionStart":
		body["source"] = "startup"
	case "UserPromptSubmit":
		body["prompt"] = "list the files"
	case "PreToolUse", "PostToolUse":
		body["tool_name"] = "Bash"
		body["tool_use_id"] = call.tool
		body["tool_input"] = map[string]any{"command": "git status"}
		if call.event == "PostToolUse" {
			body["tool_response"] = map[string]any{"stdout": "ok", "stderr": "", "interrupted": false}
		}
	case "Stop":
		body["stop_hook_active"] = false
	}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func waitForHookCorrelationQueue(t *testing.T, store *audit.Store, depth int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for store.CorrelationTurnQueueSnapshot().Depth != int64(depth) {
		if time.Now().After(deadline) {
			t.Fatalf("correlation turn queue depth %d, want %d", store.CorrelationTurnQueueSnapshot().Depth, depth)
		}
		time.Sleep(time.Millisecond)
	}
}

// groupLeg is what one run of the identity calls left: the answers in call
// order and every correlation and audit table, canonical.
type groupLeg struct {
	answers []string
	tables  map[string][]string
}

// runGroupIdentityLeg runs the waves of calls. In each wave it holds the
// turn of both sessions, queues every call of the wave on its session's turn
// in call order (so every leg correlates a session in the same order),
// releases the turns and waits for every answer. Then it waits for the store
// to go quiet.
func runGroupIdentityLeg(t *testing.T, limits audit.CorrelationGroupLimits, cwd string) groupLeg {
	t.Helper()
	setHookCorrelationGroupLimits(t, limits)
	f := newAuditFailureHookFixture(t, "open")
	handler := f.api.handleAgentHook("claudecode")
	var answers []string
	for _, wave := range groupIdentityCalls() {
		var releases []func()
		for _, session := range []string{"s8-identity-a", "s8-identity-b"} {
			_, release, err := f.api.store.JoinCorrelationGroup(t.Context(), "claudecode\x00"+session, limits)
			if err != nil {
				t.Fatal(err)
			}
			releases = append(releases, release)
		}
		got := make([]string, len(wave))
		var wg sync.WaitGroup
		for i, call := range wave {
			body := groupHookBody(t, cwd, call)
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
				got[i] = fmt.Sprintf("%d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
			}()
			waitForHookCorrelationQueue(t, f.api.store, i+1)
		}
		for _, release := range releases {
			release()
		}
		wg.Wait()
		answers = append(answers, got...)
	}
	waitForQuietAuditStore(t, f.path)
	return groupLeg{answers: answers, tables: dumpCanonicalCorrelation(t, f.path)}
}

func waitForQuietAuditStore(t *testing.T, path string) {
	t.Helper()
	db := openGroupAuditDB(t, path)
	defer db.Close()
	count := func() (n int) {
		_ = db.QueryRow(`SELECT (SELECT COUNT(*) FROM audit_events) + (SELECT COUNT(*) FROM correlation_observations)`).Scan(&n)
		return n
	}
	last, stable := count(), 0
	for deadline := time.Now().Add(15 * time.Second); stable < 5 && time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		if n := count(); n == last {
			stable++
		} else {
			last, stable = n, 0
		}
	}
}

func openGroupAuditDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

var (
	groupUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	groupHex  = regexp.MustCompile(`[0-9a-f]{16,}`)
	// groupVolatile are the columns and JSON keys that hold wall-clock time or
	// durations, which no two runs share, and the agent_sequence of an audit
	// row: the position of the agent lifecycle when the row was written,
	// after the correlation turn, which the calls of one wave reach in any
	// order on every path (the correlation cursor sequence is compared).
	groupVolatile = regexp.MustCompile(`(?i)(time|_at$|^at$|timestamp|expires|elapsed|latency|duration|_ms$|_ns$|unix|^agent_sequence$)`)
	// groupVolatileText are the same values inside free text (the details
	// column of a compatibility row).
	groupVolatileText = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T[0-9:.]+Z|((elapsed_ms|latency_ms|duration_ms|agent_sequence)\W{1,4})\d+`)
)

// groupCanon renames the minted IDs and digests of one run (see
// dumpCanonicalCorrelation), so two runs that minted different random IDs
// for the same calls compare equal; an ID no correlation table names (a
// random audit row ID) becomes "#".
type groupCanon struct {
	names   map[string]string
	growing bool
}

func (c *groupCanon) rename(value string) string {
	replace := func(token string) string {
		if name, ok := c.names[token]; ok {
			return name
		}
		if !c.growing {
			return "#"
		}
		name := fmt.Sprintf("<%d>", len(c.names))
		c.names[token] = name
		return name
	}
	value = groupVolatileText.ReplaceAllString(value, "${1}~")
	value = groupUUID.ReplaceAllStringFunc(value, replace)
	return groupHex.ReplaceAllStringFunc(value, replace)
}

func (c *groupCanon) value(raw any) string {
	switch v := raw.(type) {
	case nil:
		return "NULL"
	case []byte:
		return c.text(string(v))
	case string:
		return c.text(v)
	default:
		return fmt.Sprint(v)
	}
}

// text canonicalizes a column value; JSON loses its volatile keys.
func (c *groupCanon) text(value string) string {
	var decoded any
	if (strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[")) && json.Unmarshal([]byte(value), &decoded) == nil {
		out, _ := json.Marshal(c.json(decoded))
		return string(out)
	}
	return c.rename(value)
}

func (c *groupCanon) json(value any) any {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make([][2]any, 0, len(keys))
		for _, key := range keys {
			if groupVolatile.MatchString(key) {
				continue
			}
			out = append(out, [2]any{key, c.json(v[key])})
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = c.json(v[i])
		}
		return out
	case string:
		return c.text(v)
	default:
		return v
	}
}

// groupNamedTables name the IDs they hold, in their canonical row order.
var groupNamedTables = []string{
	"correlation_connector_instances", "correlation_events", "correlation_cursors",
	"correlation_pending_operations", "correlation_identifiers", "correlation_identity_claims",
	"correlation_relationships", "correlation_relationship_evidence", "correlation_receipts",
}

// groupRecordTables are also written after the turn; an ID only they hold
// (a random record ID) compares as "#". Their rows also carry the agent
// lifecycle the call reached when its record was written (phase, sequence,
// step), which the calls of one wave reach in any order on every path, the
// serial one too: only their kind and the correlation IDs they carry are
// compared.
var groupRecordTables = []string{"correlation_observations", "audit_events"}

var (
	groupRecordColumns = regexp.MustCompile(`^(action|target|actor|severity|event_name|signal|bucket|status|connector|session_id|tool_id|agent_id|semantic_event_id|logical_event_id|turn_id|tool_invocation_id)$`)
	groupRecordKeys    = regexp.MustCompile(`(semantic_event_id|logical_event_id|tool_invocation_id|turn_id|agent_id|session_id|tool_use_id|connector_instance_id)$`)
)

// recordIDs lists the correlation IDs a JSON value carries, by key.
func (c *groupCanon) recordIDs(prefix string, value any, out *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, inner := range v {
			if text, ok := inner.(string); ok && groupRecordKeys.MatchString(key) {
				*out = append(*out, prefix+key+"="+c.rename(text))
				continue
			}
			c.recordIDs(prefix+key+".", inner, out)
		}
	case []any:
		for _, inner := range v {
			c.recordIDs(prefix, inner, out)
		}
	}
}

// dumpCanonicalCorrelation reads every correlation and audit table. Every
// correlation event is named by the bytes of the call that made it (its
// fingerprint), the same in every run; every other minted ID or digest by
// its first appearance in the rows sorted by their text with the unknown
// IDs masked. The sessions of the identity calls run side by side, so the
// row order of a table is not the comparison: its canonical rows are.
func dumpCanonicalCorrelation(t *testing.T, path string) map[string][]string {
	t.Helper()
	db := openGroupAuditDB(t, path)
	defer db.Close()
	canon := &groupCanon{names: map[string]string{}}
	events, err := db.Query(`SELECT semantic_event_id, fingerprint_sha256 FROM correlation_events`)
	if err != nil {
		t.Fatal(err)
	}
	for events.Next() {
		var semantic, fingerprint string
		if err := events.Scan(&semantic, &fingerprint); err != nil {
			t.Fatal(err)
		}
		canon.names[semantic] = "E" + fingerprint[:12]
		canon.names[fingerprint] = "F" + fingerprint[:12]
	}
	events.Close()
	type row struct {
		columns []string
		values  []any
	}
	read := func(table string) []row {
		rows, err := db.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var out []row
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			out = append(out, row{columns, values})
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	renderRecord := func(r row) string {
		var line []string
		for i, column := range r.columns {
			if groupRecordColumns.MatchString(column) {
				line = append(line, column+"="+canon.value(r.values[i]))
				continue
			}
			text, ok := r.values[i].(string)
			if raw, isBytes := r.values[i].([]byte); isBytes {
				text, ok = string(raw), true
			}
			var decoded any
			if ok && json.Unmarshal([]byte(text), &decoded) == nil {
				var ids []string
				canon.recordIDs(column+".", decoded, &ids)
				sort.Strings(ids)
				line = append(line, ids...)
			}
		}
		return strings.Join(line, " ")
	}
	render := func(r row) string {
		var line []string
		for i, column := range r.columns {
			if groupVolatile.MatchString(column) {
				continue
			}
			line = append(line, column+"="+canon.value(r.values[i]))
		}
		return strings.Join(line, " ")
	}
	tables := map[string][]string{}
	dump := func(table string, growing bool) {
		rows := read(table)
		canon.growing = false
		render := render
		if !growing {
			render = renderRecord
		}
		masked := make([]string, len(rows))
		for i := range rows {
			masked[i] = render(rows[i])
		}
		order := make([]int, len(rows))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return masked[order[a]] < masked[order[b]] })
		canon.growing = growing
		for _, i := range order {
			tables[table] = append(tables[table], render(rows[i]))
		}
	}
	for _, table := range groupNamedTables {
		dump(table, true)
	}
	for _, table := range groupRecordTables {
		dump(table, false)
	}
	return tables
}

// The same hook calls of two sessions, each session in the same order, give
// the same answers and the same correlation results whether every
// occurrence has its own transaction (groups of one, the serial path), a few
// share one, or all of them share one (S8 design section 13): the same IDs
// (semantic event, logical event, tool invocation, turn, agent, after
// renaming the random ones canonically), the same relationships and pending
// operations, the same cursor end state, and audit rows that carry the same
// correlation IDs.
func TestHookCorrelationGroupVerdictIdentity(t *testing.T) {
	cwd := filepath.Join(os.TempDir(), "s8-group-identity")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	var serial groupLeg
	for _, leg := range []struct {
		name   string
		limits audit.CorrelationGroupLimits
	}{
		{"serial", audit.CorrelationGroupLimits{Occurrences: 1}},
		// The serial path again: a difference here is a field the harness
		// must not compare (it depends on timing on every path).
		{"serial-repeat", audit.CorrelationGroupLimits{Occurrences: 1}},
		// The production hold: an unbounded one keeps the writer from the
		// session start verdict's own records while a wave correlates, and
		// under -race the wave's tool calls then wait past the session start
		// gate (refused SESSION-START-PENDING).
		{"groups-of-4", audit.CorrelationGroupLimits{Occurrences: 4, Hold: hookCorrelationGroupLimits.Hold}},
		{"production-limits", hookCorrelationGroupLimits},
	} {
		var got groupLeg
		t.Run(leg.name, func(t *testing.T) { got = runGroupIdentityLeg(t, leg.limits, cwd) })
		if t.Failed() {
			return
		}
		if leg.name == "serial" {
			serial = got
			if calls := len(slices.Concat(groupIdentityCalls()...)); len(serial.tables["correlation_events"]) < calls {
				t.Fatalf("serial leg stored %d correlation events for %d calls", len(serial.tables["correlation_events"]), calls)
			}
			continue
		}
		for i := range serial.answers {
			if serial.answers[i] != got.answers[i] {
				t.Errorf("%s: answer %d (%v) differs:\nserial  %s\ngrouped %s", leg.name, i, slices.Concat(groupIdentityCalls()...)[i], serial.answers[i], got.answers[i])
			}
		}
		for _, table := range append(slices.Clone(groupNamedTables), groupRecordTables...) {
			want, have := serial.tables[table], got.tables[table]
			if !slices.Equal(want, have) {
				for i := 0; i < max(len(want), len(have)); i++ {
					var w, h string
					if i < len(want) {
						w = want[i]
					}
					if i < len(have) {
						h = have[i]
					}
					if w != h {
						at := 0
						for at < min(len(w), len(h)) && w[at] == h[at] {
							at++
						}
						from := max(at-300, 0)
						t.Errorf("%s: %s row %d differs at byte %d (%d vs %d rows):\nserial  ...%.600s\ngrouped ...%.600s", leg.name, table, i, at, len(want), len(have), w[from:], h[from:])
						break
					}
				}
			}
		}
	}
}

// perUserHookAllowed reports whether a Claude Code hook answer lets the call
// run: an explicit allow, or no decision at all (the hook then runs it).
func perUserHookAllowed(out []byte) bool {
	var answer map[string]any
	if json.Unmarshal(out, &answer) != nil {
		return false
	}
	if action, ok := answer["action"].(string); ok {
		return action == "allow"
	}
	if specific, ok := answer["hookSpecificOutput"].(map[string]any); ok {
		if decision, ok := specific["permissionDecision"].(string); ok {
			return decision == "allow"
		}
	}
	if decision, ok := answer["decision"].(string); ok {
		return decision != "block" && decision != "deny"
	}
	return true
}

// Many sessions in flight at once through the real hook path, small groups
// and a short hold so the groups turn over: every call is allowed and
// correlated once. Run with -race.
func TestHookCorrelationGroupConcurrentSessionsRace(t *testing.T) {
	setHookCorrelationGroupLimits(t, audit.CorrelationGroupLimits{Occurrences: 5, Hold: 2 * time.Millisecond})
	f := newAuditFailureHookFixture(t, "open")
	handler := f.api.handleAgentHook("claudecode")
	cwd := t.TempDir()
	const sessions, perSession = 4, 15
	var wg sync.WaitGroup
	errs := make(chan string, sessions*perSession)
	for s := 0; s < sessions; s++ {
		session := fmt.Sprintf("s8-race-%d", s)
		for _, event := range []string{"SessionStart", "UserPromptSubmit"} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
				bytes.NewReader(groupHookBody(t, cwd, groupHookCall{session, event, ""}))))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s: %d %s", session, event, rec.Code, rec.Body)
			}
		}
		for i := 0; i < perSession; i++ {
			body := groupHookBody(t, cwd, groupHookCall{session, "PreToolUse", fmt.Sprintf("toolu_r%d_%d", s, i)})
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
				if rec.Code != http.StatusOK || !perUserHookAllowed(rec.Body.Bytes()) {
					errs <- fmt.Sprintf("%d %.200s", rec.Code, rec.Body)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	db := openGroupAuditDB(t, f.path)
	defer db.Close()
	var events, operations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM correlation_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(DISTINCT operation_id) FROM correlation_pending_operations`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if want := sessions * (perSession + 2); events != want {
		t.Fatalf("%d correlation events, want %d", events, want)
	}
	if operations != sessions*perSession {
		t.Fatalf("%d tool operations, want %d", operations, sessions*perSession)
	}
	if depth := f.api.store.CorrelationTurnQueueSnapshot().Depth; depth != 0 {
		t.Fatalf("%d occurrences still wait for the correlation turn", depth)
	}
}
