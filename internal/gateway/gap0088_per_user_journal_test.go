// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"database/sql"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A per-user gateway runs no hook delivery recovery, so its receipt-backed
// calls keep no journal row: two synchronous=FULL fsyncs per call held the
// answer on a disk slow to flush (rel-1-0-10 GAP-0088). The call is still
// audited from the answer the hook confirmed, and its decision record keeps
// the call's stable ID.
func TestGAP0088PerUserReceiptCallWritesNoJournalRow(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = "per_user"
	if f.api.journalsHookDeliveries() {
		t.Fatal("a per-user gateway journals hook deliveries")
	}
	const session = "g88-per-user"
	body := managedHookBody(session, "PreToolUse")
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+"/api/v1/claudecode/hook", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	responses := make(chan *http.Response, 1)
	failures := make(chan error, 1)
	go func() {
		response, err := f.server.Client().Do(request)
		if err != nil {
			failures <- err
			return
		}
		responses <- response
	}()
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal(err)
	}
	var response *http.Response
	select {
	case response = <-responses:
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not offer the answer")
	}
	defer response.Body.Close()
	buffered := bufio.NewReader(response.Body)
	line, err := buffered.ReadString('\n')
	if response.StatusCode != http.StatusOK || err != nil || !strings.Contains(line, `"action":"allow"`) {
		t.Fatalf("per-user answer: status=%d line=%q error=%v", response.StatusCode, line, err)
	}
	if _, err := io.WriteString(writer, hookexec.HookDeliveryReceiptAck); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	_, _ = io.Copy(io.Discard, buffered)
	if got := f.audited(t, session)[session]; got != "allow" {
		t.Fatalf("receipt-confirmed per-user call audit = %q, want allow", got)
	}
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The journal table is created by the first journal write
	// (execHookDeliveryJournal); a row written and settled leaves the table
	// behind, so the table itself shows whether the call wrote one.
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?`, "table", "hook_delivery_journal").Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("a per-user call wrote a hook delivery journal row")
	}
	var decisions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id LIKE '%-decision'`).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 {
		t.Fatalf("per-user call has %d decision records with its stable ID, want 1", decisions)
	}
}
