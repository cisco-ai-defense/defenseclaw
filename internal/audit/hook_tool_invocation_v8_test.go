// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The lookup opens the database through a read-only SQLite URI, so the
// path is escaped (spaces here) and, on Windows, written as file:///C:/...;
// it never creates a database that is not there. The gateway package
// matches records from the real v8 emitter.
func TestFindHookToolInvocationOpensTheDatabaseReadOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC()
	_, err = db.Exec(`CREATE TABLE audit_events (timestamp TEXT, connector TEXT, event_name TEXT, tool_id TEXT, projected_record_json TEXT)`)
	if err == nil {
		_, err = db.Exec(`INSERT INTO audit_events VALUES (?, 'claudecode', 'tool.invocation.requested', 'toolu_x', ?)`,
			stamp.Format(time.RFC3339Nano), `{"connector":"claudecode","body":{"gen_ai.tool.call.id":"toolu_x","user.id":"1000"}}`)
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	query := HookToolInvocationQuery{Connector: "claudecode", ToolCallID: "toolu_x", Since: stamp.Add(-time.Second), UserID: "1000"}
	evidence, err := FindHookToolInvocation(context.Background(), path, query)
	if err != nil || !evidence.Matched {
		t.Fatalf("the record must match: %+v %v", evidence, err)
	}
	missing := filepath.Join(dir, "missing.db")
	if _, err := FindHookToolInvocation(context.Background(), missing, query); err == nil {
		t.Fatal("a missing database must be an error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("the lookup must not create a database: %v", err)
	}
	if _, err := FindHookToolInvocation(context.Background(), "audit.db", query); err == nil {
		t.Fatal("a relative database path must be refused")
	}
	if _, err := FindHookToolInvocation(context.Background(), path, HookToolInvocationQuery{Connector: "claudecode"}); err == nil {
		t.Fatal("a query without a tool call id and start must be refused")
	}
}
