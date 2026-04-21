// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

type mockTel struct {
	byRule [][3]string // scanner, ruleID, severity
}

func (m *mockTel) RecordScanFindingByRule(_ context.Context, scanner, ruleID, severity string) {
	m.byRule = append(m.byRule, [3]string{scanner, ruleID, severity})
}

func TestEmitScanResult_TableDriven(t *testing.T) {
	cases := []struct {
		name        string
		scanner     string
		wantScanner string // v7 gateway-event-envelope schema enum
		findings    []Finding
		wantN       int // EventScanFinding count
	}{
		{"skill", "skill-scanner", "skill", []Finding{{ID: "1", Severity: SeverityHigh, Title: "t", Scanner: "skill-scanner", Category: "x"}}, 1},
		{"mcp", "mcp-scanner", "mcp", []Finding{{ID: "1", Severity: SeverityMedium, Title: "m", Scanner: "mcp-scanner"}}, 1},
		{"plugin", "plugin-scanner", "plugin", []Finding{{ID: "1", Severity: SeverityLow, Title: "p", Scanner: "plugin-scanner", RuleID: "r1"}}, 1},
		{"aibom", "aibom", "aibom", []Finding{{ID: "1", Severity: SeverityInfo, Title: "i", Scanner: "aibom"}}, 1},
		{"codeguard", "codeguard", "codeguard", []Finding{{ID: "CG-1", Severity: SeverityCritical, Title: "c", Scanner: "codeguard", RuleID: "CG-1"}}, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var emitted []gatewaylog.Event
			w, err := gatewaylog.New(gatewaylog.Config{})
			if err != nil {
				t.Fatal(err)
			}
			w.WithFanout(func(e gatewaylog.Event) { emitted = append(emitted, e) })

			r := &ScanResult{
				Scanner:   tc.scanner,
				Target:    "/tmp/target",
				Timestamp: time.Now().UTC(),
				Findings:  tc.findings,
				Duration:  time.Millisecond * 100,
			}
			_, err = EmitScanResult(context.Background(), w, nil, &mockTel{}, r, AgentIdentity{
				AgentID: "agent-1", AgentName: "n", AgentInstanceID: "i1", SidecarInstanceID: "s1",
			})
			if err != nil {
				t.Fatalf("EmitScanResult: %v", err)
			}
			var scanCount, findingCount int
			for _, e := range emitted {
				switch e.EventType {
				case gatewaylog.EventScan:
					scanCount++
					if e.Scan == nil || e.Scan.Scanner != tc.wantScanner {
						t.Fatalf("EventScan scanner=%q want=%q payload=%+v", func() string {
							if e.Scan == nil {
								return ""
							}
							return e.Scan.Scanner
						}(), tc.wantScanner, e.Scan)
					}
				case gatewaylog.EventScanFinding:
					findingCount++
					if e.ScanFinding == nil || e.ScanFinding.Scanner != tc.wantScanner {
						t.Fatalf("EventScanFinding scanner=%q want=%q payload=%+v", func() string {
							if e.ScanFinding == nil {
								return ""
							}
							return e.ScanFinding.Scanner
						}(), tc.wantScanner, e.ScanFinding)
					}
					if e.ScanFinding.RuleID == "" {
						t.Fatal("expected non-empty rule_id")
					}
				}
			}
			if scanCount != 1 {
				t.Fatalf("want 1 EventScan, got %d", scanCount)
			}
			if findingCount != tc.wantN {
				t.Fatalf("want %d EventScanFinding, got %d", tc.wantN, findingCount)
			}
		})
	}
}

func TestEmitScanResult_SharedScanID(t *testing.T) {
	var emitted []gatewaylog.Event
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.WithFanout(func(e gatewaylog.Event) { emitted = append(emitted, e) })

	r := &ScanResult{
		Scanner: "skill-scanner", Target: "t", Timestamp: time.Now().UTC(),
		Findings: []Finding{
			{ID: "a", Severity: SeverityHigh, Title: "one", Scanner: "skill-scanner"},
			{ID: "b", Severity: SeverityLow, Title: "two", Scanner: "skill-scanner"},
		},
		Duration: time.Second,
	}
	scanID, err := EmitScanResult(context.Background(), w, nil, &mockTel{}, r, AgentIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	var sawScan, sawIDs []string
	for _, e := range emitted {
		if e.Scan != nil {
			sawScan = append(sawScan, e.Scan.ScanID)
		}
		if e.ScanFinding != nil {
			sawIDs = append(sawIDs, e.ScanFinding.ScanID)
		}
	}
	if len(sawScan) != 1 || len(sawIDs) != 2 {
		t.Fatalf("scan payloads: %d %d", len(sawScan), len(sawIDs))
	}
	for _, id := range append(sawScan, sawIDs...) {
		if id != scanID {
			t.Fatalf("scan_id mismatch: want %q got %q", scanID, id)
		}
	}
}

func TestEnsureRuleID_Synthesis(t *testing.T) {
	f := Finding{ID: "x", Severity: SeverityHigh, Title: "Hello World!", Scanner: "skill-scanner"}
	got := EnsureRuleID(&f, "skill-scanner")
	if got == "" || !strings.Contains(got, "skill.") {
		t.Fatalf("got %q", got)
	}
}

func TestEmitScanResult_ConcurrentScanIDs(t *testing.T) {
	const n = 10
	var wg sync.WaitGroup
	ids := make([]string, n)
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, _ := gatewaylog.New(gatewaylog.Config{})
			r := &ScanResult{
				Scanner: "mcp-scanner", Target: "t", Timestamp: time.Now().UTC(),
				Findings: []Finding{{ID: "1", Severity: SeverityInfo, Title: "t", Scanner: "mcp-scanner"}},
				Duration: time.Millisecond,
			}
			id, err := EmitScanResult(context.Background(), w, nil, nil, r, AgentIdentity{})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			ids[i] = id
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			t.Fatal("empty scan id")
		}
		if seen[id] {
			t.Fatalf("duplicate scan_id %q", id)
		}
		seen[id] = true
	}
}
