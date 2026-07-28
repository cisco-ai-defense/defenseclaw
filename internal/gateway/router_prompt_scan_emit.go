// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// streamScanCorrelation mirrors streamEnvelope into the audit scan pipeline
// so scan_findings rows align with other Bifrost stream events and the
// session correlator receives session_id + agent_instance_id.
func (r *EventRouter) streamScanCorrelation(sessionKey string) audit.ScanCorrelation {
	env := r.streamEnvelope(context.Background(), sessionKey)
	return audit.ScanCorrelation{
		RunID:           env.RunID,
		RequestID:       env.RequestID,
		SessionID:       env.SessionID,
		TraceID:         env.TraceID,
		AgentID:         env.AgentID,
		AgentName:       env.AgentName,
		AgentInstanceID: env.AgentInstanceID,
		Connector:       env.Connector,
	}
}

func guardrailActionToScanVerdict(action string) string {
	switch strings.TrimSpace(action) {
	case guardrailActionAllow:
		return "clean"
	case guardrailActionAlert:
		return "warn"
	case guardrailActionBlock, guardrailActionConfirm:
		return "block"
	default:
		return ""
	}
}

func verdictSeverityToScanner(sev string) scanner.Severity {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return scanner.SeverityCritical
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}

func sessionPromptScannerName(v *ScanVerdict) string {
	if v != nil && strings.TrimSpace(v.Scanner) != "" {
		return v.Scanner
	}
	return "session-prompt"
}

// buildSessionPromptScanResult converts a stream-path prompt verdict into a
// ScanResult for LogScanWithCorrelation. It preserves source facts for the
// central per-destination redaction boundary.
func buildSessionPromptScanResult(verdict *ScanVerdict, messageID string, elapsed time.Duration) *scanner.ScanResult {
	if verdict == nil || messageID == "" {
		return nil
	}
	scName := sessionPromptScannerName(verdict)
	sev := verdictSeverityToScanner(verdict.Severity)
	nfs := NormalizeScanVerdict(verdict)
	if len(nfs) == 0 {
		nfs = []NormalizedFinding{{
			CanonicalID: "session-prompt",
			Source:      scName,
			OriginalID:  "session-prompt",
			Category:    CatGeneral,
			Severity:    verdict.Severity,
			Title:       stripLogInjectionRunes(verdict.Reason),
		}}
	}
	findings := make([]scanner.Finding, 0, len(nfs))
	for _, nf := range nfs {
		title := strings.TrimSpace(stripLogInjectionRunes(nf.Title))
		if title == "" {
			title = nf.CanonicalID
		}
		findings = append(findings, scanner.Finding{
			RuleID:   nf.CanonicalID,
			Title:    title,
			Severity: sev,
			Category: nf.Category,
			Scanner:  scName,
		})
	}
	return &scanner.ScanResult{
		Scanner:    scName,
		Target:     "message:" + messageID,
		Timestamp:  time.Now().UTC(),
		Findings:   findings,
		Duration:   elapsed,
		TargetType: "prompt",
	}
}

func (r *EventRouter) persistSessionPromptScan(verdict *ScanVerdict, sessionKey, messageID string, elapsed time.Duration) {
	if r == nil || r.logger == nil || verdict == nil || sessionKey == "" || messageID == "" {
		return
	}
	result := buildSessionPromptScanResult(verdict, messageID, elapsed)
	if result == nil {
		return
	}
	env := r.streamEnvelope(context.Background(), sessionKey)
	ctx := audit.ContextWithEnvelope(context.Background(), env)
	corr := r.streamScanCorrelation(sessionKey)
	vStr := guardrailActionToScanVerdict(verdict.Action)
	if err := r.logger.LogScanWithCorrelation(ctx, result, vStr, corr); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] session.message prompt-scan LogScan: %v\n", err)
	}
}
