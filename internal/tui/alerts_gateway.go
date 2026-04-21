// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

type alertMergeKind uint8

const (
	alertMergeAudit alertMergeKind = iota
	alertMergeScan
)

// alertMergeItem is one timeline entry: either a SQLite audit alert or a scan roll-up.
type alertMergeItem struct {
	Kind  alertMergeKind
	Audit *audit.Event
	Scan  *ScanBlock
}

type alertFlatKind uint8

const (
	alertFlatAudit alertFlatKind = iota
	alertFlatScanHead
	alertFlatScanFinding
)

// alertFlatRow is one selectable row in the Alerts list (audit row, scan parent, or finding child).
type alertFlatRow struct {
	Kind    alertFlatKind
	Event   *audit.Event
	ScanID  string
	FindIdx int // >=0 for finding rows
}

func mergeAlertsWithScans(audits []audit.Event, scans []*ScanBlock) []alertMergeItem {
	i, j := 0, 0
	out := make([]alertMergeItem, 0, len(audits)+len(scans))
	for i < len(audits) && j < len(scans) {
		at := audits[i].Timestamp
		st := scans[j].TS
		if at.After(st) {
			out = append(out, alertMergeItem{Kind: alertMergeAudit, Audit: &audits[i]})
			i++
		} else {
			out = append(out, alertMergeItem{Kind: alertMergeScan, Scan: scans[j]})
			j++
		}
	}
	for i < len(audits) {
		out = append(out, alertMergeItem{Kind: alertMergeAudit, Audit: &audits[i]})
		i++
	}
	for j < len(scans) {
		out = append(out, alertMergeItem{Kind: alertMergeScan, Scan: scans[j]})
		j++
	}
	return out
}

func buildAlertFlatRows(merged []alertMergeItem, expanded map[string]bool) []alertFlatRow {
	rows := make([]alertFlatRow, 0, len(merged)*2)
	for _, it := range merged {
		switch it.Kind {
		case alertMergeAudit:
			if it.Audit == nil {
				continue
			}
			ev := *it.Audit
			rows = append(rows, alertFlatRow{Kind: alertFlatAudit, Event: &ev})
		case alertMergeScan:
			if it.Scan == nil {
				continue
			}
			sid := it.Scan.Summary.ScanID
			head := syntheticScanEvent(it.Scan)
			rows = append(rows, alertFlatRow{Kind: alertFlatScanHead, Event: head, ScanID: sid, FindIdx: -1})
			if expanded[sid] {
				for fi := range it.Scan.Findings {
					fe := syntheticFindingEvent(it.Scan, fi)
					rows = append(rows, alertFlatRow{
						Kind:    alertFlatScanFinding,
						Event:   fe,
						ScanID:  sid,
						FindIdx: fi,
					})
				}
			}
		}
	}
	return rows
}

func syntheticScanEvent(b *ScanBlock) *audit.Event {
	s := b.Summary
	sev := string(s.SeverityMax)
	if sev == "" {
		sev = "INFO"
	}
	details := fmt.Sprintf("scan_id=%s scanner=%s findings=%d verdict=%s duration_ms=%d",
		s.ScanID, s.Scanner, len(b.Findings), s.Verdict, s.DurationMs)
	if s.TotalCount > 0 {
		details += fmt.Sprintf(" total=%d", s.TotalCount)
	}
	if len(s.Counts) > 0 {
		details += " counts=" + formatSeverityCounts(s.Counts)
	}
	return &audit.Event{
		ID:        "gw:scan:" + s.ScanID,
		Timestamp: b.TS,
		Action:    "scan",
		Target:    s.Target,
		Details:   details,
		Severity:  sev,
	}
}

func syntheticFindingEvent(b *ScanBlock, fi int) *audit.Event {
	if fi < 0 || fi >= len(b.Findings) {
		return &audit.Event{ID: "gw:finding:invalid", Severity: "INFO", Action: "scan-finding"}
	}
	f := b.Findings[fi]
	sev := string(f.Severity)
	if sev == "" {
		sev = "INFO"
	}
	rule := f.RuleID
	if rule == "" {
		rule = f.Category
	}
	details := fmt.Sprintf("scan_id=%s rule_id=%s line=%d title=%s",
		f.ScanID, rule, f.LineNumber, f.Title)
	return &audit.Event{
		ID:        fmt.Sprintf("gw:finding:%s:%d", f.ScanID, fi),
		Timestamp: b.TS,
		Action:    "scan-finding",
		Target:    f.Target,
		Details:   details,
		Severity:  sev,
	}
}

func formatSeverityCounts(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	return strings.Join(parts, ",")
}

func scanBlockForRow(blocks []*ScanBlock, scanID string) *ScanBlock {
	for _, b := range blocks {
		if b != nil && b.Summary.ScanID == scanID {
			return b
		}
	}
	return nil
}

// GatewayFindingDetail adapts gatewaylog.ScanFindingPayload for the detail pane.
type GatewayFindingDetail struct {
	Finding gatewaylog.ScanFindingPayload
	Scan    gatewaylog.ScanPayload
}
