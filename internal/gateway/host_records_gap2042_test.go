// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hookRecordLine is a record line as recordManagedHookDecision writes it.
func hookRecordLine(marker, decision string) string {
	return managed.FormatResilienceEvent(marker, map[string]string{
		"component": "hook", "connector": "claudecode", "hook": "pre-tool-use",
		"event": "PreToolUse", "reason": "gateway unreachable", "category": "transport",
		"fail_mode": "closed", "decision": decision, "session_id": "s-1", "tool_id": "t-1",
	})
}

// TestGAP2042ParseHostRecordLine: only a well-formed hook decision record
// counts; other records of the hook process are skipped, and a forged,
// oversized or cut line is dropped (rel-1-0-10:GAP-2042).
func TestGAP2042ParseHostRecordLine(t *testing.T) {
	block := hookRecordLine(managed.MarkerBoundary, "block")
	cases := []struct {
		name, line, decision string
		ok, hook             bool
	}{
		{"boundary block", block, "block", true, true},
		{"degraded allow", hookRecordLine(managed.MarkerDegraded, "allow"), "allow", true, true},
		{"trust advisory", managed.FormatResilienceEvent(managed.TrustAdvisoryMarker, map[string]string{"path": "/x", "label": "l", "reason": "r"}), "", true, false},
		{"provider overlay", managed.FormatResilienceEvent(managed.MarkerDegraded, map[string]string{"component": "provider_overlay", "reason": "r"}), "", true, false},
		{"other marker", managed.FormatResilienceEvent(managed.MarkerRepair, map[string]string{"component": "hook", "decision": "block"}), "", true, false},
		{"unknown decision", hookRecordLine(managed.MarkerBoundary, "maybe"), "", false, false},
		{"no decision", managed.FormatResilienceEvent(managed.MarkerBoundary, map[string]string{"component": "hook"}), "", false, false},
		{"repeated key", block + ` decision="allow"`, "", false, false},
		{"cut line", block[:len(block)-3], "", false, false},
		{"bare value", managed.MarkerBoundary + ` component=hook decision="block"`, "", false, false},
		{"bad key", managed.MarkerBoundary + ` Component="hook" decision="block"`, "", false, false},
		{"glued pairs", managed.MarkerBoundary + ` component="hook"decision="block"`, "", false, false},
		{"no marker", "hello from another program", "", false, false},
		{"empty", "", "", false, false},
		{"oversized", block + ` pad="` + strings.Repeat("a", hostRecordLineMax) + `"`, "", false, false},
	}
	for _, c := range cases {
		decision, ok, hook := parseHostRecordLine(c.line)
		if decision != c.decision || ok != c.ok || hook != c.hook {
			t.Errorf("%s: got (%q, %v, %v), want (%q, %v, %v)", c.name, decision, ok, hook, c.decision, c.ok, c.hook)
		}
	}
}

// TestGAP2042PlatformParsers: the journald JSON (MESSAGE as a string or as
// bytes), unified log ndjson (with or without the syslog tag) and event log
// XML shapes give the record lines.
func TestGAP2042PlatformParsers(t *testing.T) {
	block, allow := hookRecordLine(managed.MarkerBoundary, "block"), hookRecordLine(managed.MarkerDegraded, "allow")
	var bytesJSON []string
	for i := 0; i < len(allow); i++ {
		bytesJSON = append(bytesJSON, fmt.Sprint(allow[i]))
	}
	journal := fmt.Sprintf("{\"MESSAGE\":%q,\"__CURSOR\":\"c1\"}\n{\"MESSAGE\":[%s]}\nnot json\n", block, strings.Join(bytesJSON, ","))
	if got := parseJournalRecords([]byte(journal)); len(got) != 3 || got[0] != block || got[1] != allow || got[2] != "" {
		t.Fatalf("journal = %q", got)
	}
	if snap := countHostRecords(hostRecordRead{lines: parseJournalRecords([]byte(journal))}); snap.Blocks != 1 || snap.Allows != 1 || snap.Dropped != 1 {
		t.Fatalf("journal counts = %+v", snap)
	}

	ndjson := fmt.Sprintf("{\"eventMessage\":%q,\"processImagePath\":\"/x\"}\n{\"eventMessage\":%q}\n{\"count\":2,\"finished\":1}\n",
		"DefenseClawGateway[4242]: "+block, allow)
	if got := parseUnifiedLogRecords([]byte(ndjson), "DefenseClawGateway"); len(got) != 2 || got[0] != block || got[1] != allow {
		t.Fatalf("unified log = %q", got)
	}

	esc := func(s string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
	}
	event := func(data string) string {
		return `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='DefenseClawGateway'/>` +
			`<EventID Qualifiers='0'>3</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-27T10:00:00.000Z'/></System>` +
			`<EventData><Data>` + esc(data) + `</Data></EventData></Event>`
	}
	xmlOut := event(block) + "\r\n" + event(allow) + "\r\n"
	if got := parseEventLogRecords([]byte(xmlOut)); len(got) != 2 || got[0] != block || got[1] != allow {
		t.Fatalf("event log = %q", got)
	}
}

// TestGAP2042CountBounds: past hostRecordReadMax entries only the newest
// hostRecordReadMax are counted and the limit is reported; a capped reader
// output reports it too.
func TestGAP2042CountBounds(t *testing.T) {
	lines := make([]string, 0, hostRecordReadMax+1)
	for i := 0; i < hostRecordReadMax; i++ {
		lines = append(lines, hookRecordLine(managed.MarkerBoundary, "block"))
	}
	lines = append(lines, hookRecordLine(managed.MarkerDegraded, "allow"))
	snap := countHostRecords(hostRecordRead{lines: lines})
	if !snap.ReadLimitReached || snap.Records != hostRecordReadMax || snap.Blocks != hostRecordReadMax || snap.Allows != 0 {
		t.Fatalf("over the bound: %+v", snap)
	}
	if snap := countHostRecords(hostRecordRead{lines: lines[:3], capped: true}); !snap.ReadLimitReached || snap.Records != 3 {
		t.Fatalf("capped output: %+v", snap)
	}
	out := &hostRecordOutput{max: 4}
	if n, err := out.Write([]byte("abcdef")); n != 6 || err != nil || out.buf.String() != "abcd" || !out.capped {
		t.Fatalf("output cap: n=%d err=%v buf=%q capped=%v", n, err, out.buf.String(), out.capped)
	}
}

// fakeHostRecords swaps the process reader for one that returns lines (or
// err) and counts its reads.
func fakeHostRecords(t *testing.T, now *time.Time, lines []string, err error) (*hostRecordReader, func() int) {
	t.Helper()
	var mu sync.Mutex
	reads := 0
	h := &hostRecordReader{
		now: func() time.Time { return *now },
		read: func(ctx context.Context, source string, since time.Time) (hostRecordRead, error) {
			mu.Lock()
			reads++
			mu.Unlock()
			if want := now.Add(-hostRecordWindow); !since.Equal(want) {
				t.Errorf("since = %v, want %v", since, want)
			}
			return hostRecordRead{lines: lines}, err
		},
	}
	old := hostRecords
	hostRecords = h
	t.Cleanup(func() { hostRecords = old })
	return h, func() int { mu.Lock(); defer mu.Unlock(); return reads }
}

func waitHostRecordsRead(t *testing.T, h *hostRecordReader) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		busy := h.busy
		h.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("host record read did not finish")
}

// TestGAP2042ReaderSnapshot: the first snapshot starts a read and says it
// has not read yet; the next one has the counts; a read runs at most once
// per hostRecordReadEvery; a reader error is not readable, with the reason.
func TestGAP2042ReaderSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	lines := []string{hookRecordLine(managed.MarkerBoundary, "block"), hookRecordLine(managed.MarkerDegraded, "allow"), "forged"}
	h, reads := fakeHostRecords(t, &now, lines, nil)
	if snap := h.snapshot(); snap.Readable || snap.Reason != "not read yet" || snap.WindowHours != 24 || snap.ReadMax != hostRecordReadMax {
		t.Fatalf("first snapshot = %+v", snap)
	}
	waitHostRecordsRead(t, h)
	snap := h.snapshot()
	if !snap.Readable || snap.Records != 2 || snap.Blocks != 1 || snap.Allows != 1 || snap.Dropped != 1 || snap.LastRead == nil || !snap.LastRead.Equal(now) {
		t.Fatalf("snapshot = %+v", snap)
	}
	now = now.Add(hostRecordReadEvery - time.Second)
	h.snapshot()
	waitHostRecordsRead(t, h)
	if got := reads(); got != 1 {
		t.Fatalf("reads within the interval = %d, want 1", got)
	}
	now = now.Add(2 * time.Second)
	h.snapshot()
	waitHostRecordsRead(t, h)
	if got := reads(); got != 2 {
		t.Fatalf("reads after the interval = %d, want 2", got)
	}

	failNow := now
	f, _ := fakeHostRecords(t, &failNow, nil, errors.New("no journald on this host"))
	f.kick()
	waitHostRecordsRead(t, f)
	if snap := f.snapshot(); snap.Readable || snap.Reason != "no journald on this host" || snap.Records != 0 {
		t.Fatalf("failed read = %+v", snap)
	}
}

// TestGAP2042HostRecordsOnManagedGatewayOnly: a managed gateway gives the
// count to root in /health and in /status; an ordinary account's /health
// and a per-user gateway carry none.
func TestGAP2042HostRecordsOnManagedGatewayOnly(t *testing.T) {
	now := time.Now()
	h, _ := fakeHostRecords(t, &now, []string{hookRecordLine(managed.MarkerBoundary, "block")}, nil)
	h.kick()
	waitHostRecordsRead(t, h)
	get := func(handler http.HandlerFunc, ctx context.Context) string {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		return response.Body.String()
	}
	standalone := &config.Config{DeploymentMode: "managed_enterprise"}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, standalone)
	user := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1004, Name: "hr-alice"})
	root := withManagedHookPeer(context.Background(), managedHookPeer{UID: 0})
	if body := get(api.handleHealth, user); strings.Contains(body, `"host_records"`) {
		t.Fatalf("an ordinary account read the host records in /health: %s", body)
	}
	for name, body := range map[string]string{
		"managed /health as root": get(api.handleHealth, root),
		"managed /status":         get(api.handleStatus, context.Background()),
	} {
		if !strings.Contains(body, `"host_records":{"readable":true`) || !strings.Contains(body, `"blocks":1`) {
			t.Fatalf("%s lacks host_records: %s", name, body)
		}
	}
	perUser := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, &config.Config{})
	for name, body := range map[string]string{
		"per-user /health": get(perUser.handleHealth, context.Background()),
		"per-user /status": get(perUser.handleStatus, context.Background()),
	} {
		if strings.Contains(body, `"host_records"`) {
			t.Fatalf("%s carries host_records: %s", name, body)
		}
	}
}
