// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1794: testdata/audit-1.0.3.db.gz was written by the published 1.0.3
// gateway (46f444a78a, schema 36) for three benign Claude Code PreToolUse
// calls of session fixture-103. This tree opens it, applies its migrations,
// keeps every row and finds the calls through the partial indexes.
func TestStoreWrittenByPublished103Upgrades(t *testing.T) {
	compressed, err := os.Open(filepath.Join("testdata", "audit-1.0.3.db.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, reader); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var before int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&before); err != nil || before != 36 {
		t.Fatalf("fixture schema = %d, %v; want the 1.0.3 schema 36", before, err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("open a store the published 1.0.3 gateway wrote: %v", err)
	}
	var version, events, observations int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("schema after upgrade = %d, want %d", version, len(migrations))
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&events); err != nil || events != 29 {
		t.Fatalf("audit_events = %d, %v; want the 29 rows 1.0.3 wrote", events, err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_observations WHERE session_id = 'fixture-103'`).
		Scan(&observations); err != nil || observations == 0 {
		t.Fatalf("observations of session fixture-103 = %d, %v", observations, err)
	}
	for _, index := range sparseKeyIndexes {
		if definition := sparseIndexDefinition(t, store, index.name); !strings.Contains(definition, " WHERE ") {
			t.Errorf("%s is not partial after the upgrade: %s", index.name, definition)
		}
	}
	var calls int
	if err := store.db.QueryRow(`SELECT COUNT(DISTINCT tool_invocation_id) FROM correlation_observations
		WHERE agent_id = (SELECT agent_id FROM correlation_observations
			WHERE session_id = 'fixture-103' AND agent_id IS NOT NULL LIMIT 1)
		AND tool_invocation_id LIKE 'toolu_103_%'`).Scan(&calls); err != nil || calls != 3 {
		t.Fatalf("calls found through the agent index = %d, %v; want 3", calls, err)
	}
}
