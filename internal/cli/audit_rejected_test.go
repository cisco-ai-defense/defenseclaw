// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func withAuditRejectedFlags(t *testing.T, since string, limit int, keep, keepKnown bool) {
	t.Helper()
	previousSince, previousLimit, previousCfg, previousSeam := auditRejectedSince, auditRejectedLimit, cfg, auditRejectedKeepEnabled
	t.Cleanup(func() {
		auditRejectedSince, auditRejectedLimit, cfg, auditRejectedKeepEnabled = previousSince, previousLimit, previousCfg, previousSeam
	})
	auditRejectedSince, auditRejectedLimit = since, limit
	auditRejectedKeepEnabled = func() (bool, bool) { return keep, keepKnown }
}

func runAuditRejectedForTest(t *testing.T) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := runAuditRejected(cmd, nil)
	return out.String(), errOut.String(), err
}

func TestRunAuditRejectedWritesNewestFirstJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-2 * time.Hour)
	var rows []audit.RejectedRecordRow
	for index, result := range []string{"success", "done", "fine"} {
		rows = append(rows, audit.RejectedRecordRow{
			StoredAt: base.Add(time.Duration(index) * time.Hour), Signal: "logs", Bucket: "security",
			EventName: "defenseclaw.hook.decision", Family: "compat_hook_decision", FamilySchemaVersion: 1,
			ReasonCode: "constraint_violation", Field: "defenseclaw.hook.result",
			ErrorText: "telemetry family build failed: constraint_violation; field defenseclaw.hook.result",
			Payload:   json.RawMessage(`{"defenseclaw.hook.result":"` + result + `"}`),
		})
	}
	if err := store.InsertRejectedRecords(t.Context(), rows, audit.RejectedRecordsDefaultRows); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	withAuditRejectedFlags(t, "90m", 10, true, true)
	cfg = &config.Config{AuditDB: path}
	out, errOut, err := runAuditRejectedForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	if errOut != "" {
		t.Fatalf("stderr while on: %q", errOut)
	}
	var results []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		var line struct {
			ReasonCode string          `json:"reason_code"`
			Field      string          `json:"field"`
			Error      string          `json:"error"`
			Payload    json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("line %q: %v", scanner.Text(), err)
		}
		if line.ReasonCode != "constraint_violation" || line.Field != "defenseclaw.hook.result" || line.Error == "" {
			t.Fatalf("line=%s", scanner.Text())
		}
		var payload map[string]string
		if err := json.Unmarshal(line.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		results = append(results, payload["defenseclaw.hook.result"])
	}
	if strings.Join(results, ",") != "fine,done" {
		t.Fatalf("--since 90m newest first = %v, want fine,done", results)
	}

	// The read-only open never migrates or writes the database.
	reader, err := audit.OpenReadOnlyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	if count, _ := reader.CountRejectedRecords(t.Context()); count != 3 {
		t.Fatalf("rows=%d after listing", count)
	}
}

func TestRunAuditRejectedNotesTheStoreIsOffAndAMissingDatabase(t *testing.T) {
	withAuditRejectedFlags(t, "", 100, false, true)
	cfg = &config.Config{AuditDB: filepath.Join(t.TempDir(), "missing", "audit.db")}
	out, errOut, err := runAuditRejectedForTest(t)
	if err != nil || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if !strings.Contains(errOut, "keep_rejected_records is off") ||
		!strings.Contains(errOut, "defenseclaw config set observability.local.keep_rejected_records true") ||
		!strings.Contains(errOut, "no audit database") {
		t.Fatalf("stderr=%q", errOut)
	}
}

func TestAuditRejectedFlagsAreUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		since string
		limit int
	}{{"", 0}, {"", audit.RejectedRecordsMaxListLimit + 1}, {"yesterday", 10}} {
		withAuditRejectedFlags(t, tc.since, tc.limit, true, true)
		cmd := &cobra.Command{}
		cmd.SetErr(&bytes.Buffer{})
		if _, err := checkAuditRejectedFlags(cmd, time.Now()); err == nil || !strings.Contains(err.Error(), "audit rejected:") {
			t.Fatalf("since=%q limit=%d: error %v", tc.since, tc.limit, err)
		}
	}
	if auditRejectedCmd.Annotations[secureClientAbsentAnnotation] != "true" {
		t.Fatal("audit rejected is not hidden on Secure Client")
	}
}

func TestAuditRejectedRefusesAStandardUserOnAManagedWindowsComputer(t *testing.T) {
	previousHost, previousAdmin := auditExportManagedHost, auditExportCallerIsAdministrator
	t.Cleanup(func() { auditExportManagedHost, auditExportCallerIsAdministrator = previousHost, previousAdmin })
	auditExportManagedHost = func() bool { return true }
	auditExportCallerIsAdministrator = func() bool { return false }
	t.Setenv("DEFENSECLAW_CONFIG", "")
	t.Setenv("DEFENSECLAW_HOME", "")
	withAuditRejectedFlags(t, "", 100, true, true)
	cmd := &cobra.Command{}
	cmd.SetErr(&bytes.Buffer{})
	err := auditRejectedPersistentPreRunE(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "the rejected-record store of a managed computer can be read only from an elevated Administrator prompt") {
		t.Fatalf("standard user error=%v", err)
	}
}

func TestAuditRejectedOffNoteNamesNoPerUserCommandOnAManagedComputer(t *testing.T) {
	withAuditRejectedFlags(t, "", 100, false, true)
	if note := auditRejectedOffNote(true); strings.Contains(note, "defenseclaw ") || !strings.Contains(note, "managed configuration") {
		t.Fatalf("managed note=%q", note)
	}
	if note := auditRejectedOffNote(false); !strings.Contains(note, "defenseclaw config set observability.local.keep_rejected_records true") {
		t.Fatalf("per-user note=%q", note)
	}
	withAuditRejectedFlags(t, "", 100, true, true)
	if note := auditRejectedOffNote(true); note != "" {
		t.Fatalf("note while on=%q", note)
	}
}
