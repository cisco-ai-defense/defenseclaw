// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// A failed export says only why it failed: it neither reports lines written
// nor leaves an output file (GAP-1044). A database without audit_events is
// refused before the output is created; a failure after the output was
// created removes it.
func TestRunAuditExportFailureWritesNothing(t *testing.T) {
	prevDB, prevOut, prevForce := auditExportDB, auditExportOut, auditExportForce
	prevConn, prevLimit, prevAct, prevCfg := auditExportConnector, auditExportLimit, auditExportIncludeActivity, cfg
	t.Cleanup(func() {
		auditExportDB, auditExportOut, auditExportForce = prevDB, prevOut, prevForce
		auditExportConnector, auditExportLimit, auditExportIncludeActivity, cfg = prevConn, prevLimit, prevAct, prevCfg
	})
	for _, tc := range []struct {
		name, schema, want string
	}{
		{"database without audit_events", `CREATE TABLE notes (n TEXT)`, "no audit_events table"},
		{"audit_events the export cannot read", `CREATE TABLE audit_events (id TEXT)`, "audit export:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "retained.db")
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.schema); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			cfg, auditExportDB, auditExportForce = nil, dbPath, false
			auditExportConnector, auditExportLimit, auditExportIncludeActivity = "", 5, false
			auditExportOut = filepath.Join(dir, "out.jsonl")
			var stderr bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetErr(&stderr)
			err = runAuditExport(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runAuditExport = %v, want an error with %q", err, tc.want)
			}
			if strings.Contains(stderr.String(), "Wrote") {
				t.Errorf("a failed export reported a written output: %q", stderr.String())
			}
			if _, statErr := os.Lstat(auditExportOut); !os.IsNotExist(statErr) {
				t.Errorf("a failed export left its output file (stat err %v)", statErr)
			}
		})
	}
}
