// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type Logger struct {
	store  *Store
	splunk *SplunkForwarder
	otel   *telemetry.Provider
}

func NewLogger(store *Store) *Logger {
	return &Logger{store: store}
}

func (l *Logger) SetSplunkForwarder(sf *SplunkForwarder) {
	l.splunk = sf
}

func (l *Logger) SetOTelProvider(p *telemetry.Provider) {
	l.otel = p
}

// LogScan persists a scan result to SQLite, forwards to Splunk HEC,
// and emits OTel log/metric signals.
func (l *Logger) LogScan(result *scanner.ScanResult) error {
	return l.LogScanWithVerdict(result, "")
}

// LogScanWithVerdict persists a scan result with an explicit admission verdict.
func (l *Logger) LogScanWithVerdict(result *scanner.ScanResult, verdict string) error {
	scanID := uuid.New().String()
	raw, _ := result.JSON()

	if err := l.store.InsertScanResult(
		scanID, result.Scanner, result.Target, result.Timestamp,
		result.Duration.Milliseconds(), len(result.Findings),
		string(result.MaxSeverity()), string(raw),
	); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_scan_result")
		}
		return err
	}

	for _, f := range result.Findings {
		tagsJSON, _ := json.Marshal(f.Tags)
		findingID := uuid.New().String()
		if err := l.store.InsertFinding(
			findingID, scanID, string(f.Severity), f.Title,
			f.Description, f.Location, f.Remediation, f.Scanner,
			string(tagsJSON),
		); err != nil {
			if l.otel != nil {
				l.otel.RecordAuditDBError(context.Background(), "insert_finding")
			}
			return err
		}
	}

	event := Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    "scan",
		Target:    result.Target,
		Actor:     "defenseclaw",
		Details: fmt.Sprintf("scanner=%s findings=%d max_severity=%s duration=%s",
			result.Scanner, len(result.Findings), result.MaxSeverity(), result.Duration),
		Severity: string(result.MaxSeverity()),
		RunID:    currentRunID(),
	}

	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSplunk(event)

	if l.otel != nil {
		targetType := inferTargetType(result.Scanner)
		l.otel.EmitScanResult(result, scanID, targetType, verdict)
	}

	return nil
}

// LogAction persists an action event and emits OTel lifecycle signals.
func (l *Logger) LogAction(action, target, details string) error {
	return l.LogActionWithTrace(action, target, details, "")
}

// LogActionWithTrace persists an action event with an OTel trace ID for
// cross-system correlation between Splunk O11y and Splunk local.
func (l *Logger) LogActionWithTrace(action, target, details, traceID string) error {
	event := Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Actor:     "defenseclaw",
		Details:   details,
		Severity:  "INFO",
		RunID:     currentRunID(),
		TraceID:   traceID,
	}
	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSplunk(event)

	if l.otel != nil {
		assetType := inferAssetTypeFromAction(action, details)
		l.otel.EmitLifecycleEvent(action, target, assetType, details, event.Severity, nil)
	}

	return nil
}

// LogActionWithEnforcement persists an action event with enforcement metadata
// for OTel lifecycle signals. The enforcement map may contain keys:
// "install", "file", "runtime", "source_path".
func (l *Logger) LogActionWithEnforcement(action, target, details string, enforcement map[string]string) error {
	event := Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Actor:     "defenseclaw",
		Details:   details,
		Severity:  "INFO",
		RunID:     currentRunID(),
	}
	if err := l.store.LogEvent(event); err != nil {
		if l.otel != nil {
			l.otel.RecordAuditDBError(context.Background(), "insert_event")
		}
		return err
	}
	if l.otel != nil {
		l.otel.RecordAuditEvent(context.Background(), event.Action, event.Severity)
	}
	l.forwardToSplunk(event)

	if l.otel != nil {
		assetType := inferAssetTypeFromAction(action, details)
		l.otel.EmitLifecycleEvent(action, target, assetType, details, event.Severity, enforcement)
	}

	return nil
}

func (l *Logger) forwardToSplunk(e Event) {
	if l.splunk == nil {
		return
	}
	if err := l.splunk.ForwardEvent(e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: splunk forward: %v\n", err)
		return
	}
	if shouldFlushSplunkImmediately(e.Action) {
		go func() {
			if err := l.splunk.Flush(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: splunk flush: %v\n", err)
			}
		}()
	}
}

func shouldFlushSplunkImmediately(action string) bool {
	switch action {
	case "watch-start", "watch-stop",
		"sidecar-start", "sidecar-stop",
		"sidecar-connected", "sidecar-disconnected":
		return true
	default:
		return false
	}
}

func (l *Logger) Close() {
	if l.splunk != nil {
		if err := l.splunk.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: splunk flush on close: %v\n", err)
		}
	}
}

func inferTargetType(scannerName string) string {
	switch scannerName {
	case "mcp-scanner", "mcp_scanner":
		return "mcp"
	case "skill-scanner", "skill_scanner":
		return "skill"
	case "codeguard", "aibom", "aibom-claw",
		"clawshield-vuln", "clawshield-secrets", "clawshield-pii",
		"clawshield-malware", "clawshield-injection":
		return "code"
	default:
		return "unknown"
	}
}

func inferAssetTypeFromAction(action, details string) string {
	switch {
	case contains(action, "mcp") || contains(details, "type=mcp"):
		return "mcp"
	case contains(action, "skill") || contains(details, "type=skill"):
		return "skill"
	default:
		return "skill"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
