// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestRunAuditFindingsReportsDistinctCurrentAndNewSince(t *testing.T) {
	store, err := audit.NewStore(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	base := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	finding := func(rule, evidence string) scanner.Finding {
		line := 3
		return scanner.Finding{
			Scanner: "codeguard", RuleID: rule, Severity: scanner.SeverityHigh,
			Title: rule, EvidenceSummary: evidence, Location: "/repo/main.go:3", LineNumber: &line,
		}
	}
	emit := func(at time.Time, findings ...scanner.Finding) {
		t.Helper()
		result := &scanner.ScanResult{
			Scanner: "codeguard", Target: "/repo", TargetType: "code",
			Timestamp: at, Findings: findings,
		}
		if _, emitErr := scanner.EmitScanResult(context.Background(), store, result, scanner.AgentIdentity{}); emitErr != nil {
			t.Fatalf("emit scan: %v", emitErr)
		}
	}
	emit(base, finding("CG-OLD", "old bytes"))
	emit(base.Add(time.Hour), finding("CG-NEW", "new bytes"))

	previousStore := auditStore
	previousScanner, previousTarget := auditFindingsScanner, auditFindingsTarget
	previousSince, previousNewOnly := auditFindingsSince, auditFindingsNewOnly
	previousResolved, previousLimit := auditFindingsIncludeResolved, auditFindingsLimit
	t.Cleanup(func() {
		auditStore = previousStore
		auditFindingsScanner, auditFindingsTarget = previousScanner, previousTarget
		auditFindingsSince, auditFindingsNewOnly = previousSince, previousNewOnly
		auditFindingsIncludeResolved, auditFindingsLimit = previousResolved, previousLimit
	})
	auditStore = store
	auditFindingsScanner = "codeguard"
	auditFindingsTarget = "/repo"
	auditFindingsSince = ""
	auditFindingsNewOnly = false
	auditFindingsIncludeResolved = false
	auditFindingsLimit = 100

	run := func() auditFindingsReport {
		t.Helper()
		var output bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&output)
		if runErr := runAuditFindings(cmd, nil); runErr != nil {
			t.Fatalf("run audit findings: %v", runErr)
		}
		var report auditFindingsReport
		if decodeErr := json.Unmarshal(output.Bytes(), &report); decodeErr != nil {
			t.Fatalf("decode report: %v\n%s", decodeErr, output.String())
		}
		return report
	}

	current := run()
	if !current.CurrentOnly || current.Count != 1 || len(current.DistinctFindings) != 1 ||
		current.DistinctFindings[0].RuleID != "CG-NEW" || current.DistinctFindings[0].State != "active" {
		t.Fatalf("default current report=%+v", current)
	}

	auditFindingsSince = base.Add(30 * time.Minute).Format(time.RFC3339Nano)
	auditFindingsNewOnly = true
	newOnly := run()
	if newOnly.Count != 1 || newOnly.DistinctFindings[0].RuleID != "CG-NEW" || newOnly.Since == "" {
		t.Fatalf("new-only report=%+v", newOnly)
	}

	auditFindingsNewOnly = false
	auditFindingsIncludeResolved = true
	changed := run()
	if changed.CurrentOnly || changed.Count != 2 {
		t.Fatalf("include-resolved since report=%+v", changed)
	}
}

func TestRunAuditFindingsValidatesDeltaFlags(t *testing.T) {
	previousStore := auditStore
	previousTarget := auditFindingsTarget
	previousSince, previousNewOnly, previousLimit := auditFindingsSince, auditFindingsNewOnly, auditFindingsLimit
	t.Cleanup(func() {
		auditStore = previousStore
		auditFindingsTarget = previousTarget
		auditFindingsSince, auditFindingsNewOnly, auditFindingsLimit = previousSince, previousNewOnly, previousLimit
	})
	auditStore = &audit.Store{}
	auditFindingsTarget = ""
	auditFindingsLimit = 100
	auditFindingsSince = ""
	auditFindingsNewOnly = true
	if err := runAuditFindings(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "requires --since") {
		t.Fatalf("new-only without since error=%v", err)
	}
	auditFindingsNewOnly = false
	auditFindingsSince = "yesterday"
	if err := runAuditFindings(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "invalid --since") {
		t.Fatalf("invalid since error=%v", err)
	}

	auditFindingsSince = ""
	for _, limit := range []int{0, 10_001} {
		auditFindingsLimit = limit
		if err := runAuditFindings(&cobra.Command{}, nil); err == nil ||
			!strings.Contains(err.Error(), "limit must be between 1 and 10000") {
			t.Fatalf("limit %d error=%v", limit, err)
		}
	}

	auditFindingsLimit = 100
	auditFindingsTarget = "   "
	if err := runAuditFindings(&cobra.Command{}, nil); err == nil ||
		!strings.Contains(err.Error(), "usable scan target") {
		t.Fatalf("blank target error=%v", err)
	}
}
