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

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/log"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// scanBody is the JSON structure embedded in the scan summary LogRecord body.
type scanBody struct {
	ScanID       string           `json:"scan_id"`
	Scanner      string           `json:"scanner"`
	Target       string           `json:"target"`
	TargetType   string           `json:"target_type"`
	Timestamp    string           `json:"timestamp"`
	DurationMs   int64            `json:"duration_ms"`
	FindingCount int              `json:"finding_count"`
	MaxSeverity  string           `json:"max_severity"`
	Findings     []scanBodyFinding `json:"findings"`
}

// scanBodyFinding includes only safe metadata. Sensitive fields (description,
// location, remediation) are omitted to prevent exfiltrating source content,
// secret material, or filesystem paths. Enable emit_individual_findings for
// full detail behind an explicit opt-in.
type scanBodyFinding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Scanner  string   `json:"scanner"`
	Tags     []string `json:"tags,omitempty"`
}

// EmitScanResult emits an OTel LogRecord for a completed scan and optionally
// individual finding logs. Also records scan metrics.
func (p *Provider) EmitScanResult(result *scanner.ScanResult, scanID, targetType, verdict string) {
	if !p.Enabled() {
		return
	}

	ctx := context.Background()
	maxSev := string(result.MaxSeverity())
	durationMs := float64(result.Duration.Milliseconds())

	findingCounts := map[string]int{}
	for _, f := range result.Findings {
		findingCounts[string(f.Severity)]++
	}

	p.RecordScan(ctx, result.Scanner, targetType, verdict, durationMs, findingCounts)

	if !p.LogsEnabled() {
		return
	}

	sevText, sevNum := scanSeverityToOTel(maxSev)

	body := buildScanBody(result, scanID, targetType)
	bodyJSON, _ := json.Marshal(body)

	now := time.Now()
	rec := log.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(log.Severity(sevNum))
	rec.SetSeverityText(sevText)
	rec.SetBody(log.StringValue(string(bodyJSON)))

	rec.AddAttributes(
		log.String("event.name", "scan.completed"),
		log.String("event.domain", "defenseclaw.scan"),
		log.String("defenseclaw.scan.id", scanID),
		log.String("defenseclaw.scan.scanner", result.Scanner),
		log.String("defenseclaw.scan.target", result.Target),
		log.String("defenseclaw.scan.target_type", targetType),
		log.Int("defenseclaw.scan.duration_ms", int(result.Duration.Milliseconds())),
		log.Int("defenseclaw.scan.finding_count", len(result.Findings)),
		log.String("defenseclaw.scan.max_severity", maxSev),
		log.Int("defenseclaw.scan.finding_count.critical", findingCounts["CRITICAL"]),
		log.Int("defenseclaw.scan.finding_count.high", findingCounts["HIGH"]),
		log.Int("defenseclaw.scan.finding_count.medium", findingCounts["MEDIUM"]),
		log.Int("defenseclaw.scan.finding_count.low", findingCounts["LOW"]),
		log.String("defenseclaw.scan.verdict", verdict),
	)

	p.logger.Emit(ctx, rec)

	if p.cfg.Logs.EmitIndividualFindings {
		p.emitFindingLogs(ctx, result, scanID, targetType)
	}
}

func (p *Provider) emitFindingLogs(ctx context.Context, result *scanner.ScanResult, scanID, targetType string) {
	for _, f := range result.Findings {
		sevText, sevNum := findingSeverityToOTel(string(f.Severity))
		// OTel is a persistent sink: ForSinkString always
		// redacts regardless of DEFENSECLAW_REVEAL_PII. The
		// title is static rule metadata, so it passes through
		// unchanged; description and location routinely carry
		// secret material / filesystem paths and must be
		// scrubbed before export.
		safeDesc := redaction.ForSinkString(f.Description)
		safeLoc := redaction.ForSinkString(f.Location)
		body := fmt.Sprintf("%s: %s", f.Title, safeDesc)

		rec := log.Record{}
		now := time.Now()
		rec.SetTimestamp(now)
		rec.SetObservedTimestamp(now)
		rec.SetSeverity(log.Severity(sevNum))
		rec.SetSeverityText(sevText)
		rec.SetBody(log.StringValue(body))

		attrs := []log.KeyValue{
			log.String("event.name", "scan.finding"),
			log.String("event.domain", "defenseclaw.scan"),
			log.String("defenseclaw.scan.id", scanID),
			log.String("defenseclaw.finding.id", f.ID),
			log.String("defenseclaw.finding.severity", string(f.Severity)),
			log.String("defenseclaw.finding.title", f.Title),
			log.String("defenseclaw.finding.scanner", f.Scanner),
			log.String("defenseclaw.finding.location", safeLoc),
			log.String("defenseclaw.scan.target", result.Target),
			log.String("defenseclaw.scan.target_type", targetType),
		}

		if len(f.Tags) > 0 {
			tagVals := make([]log.Value, len(f.Tags))
			for i, t := range f.Tags {
				tagVals[i] = log.StringValue(t)
			}
			attrs = append(attrs, log.Slice("defenseclaw.finding.tags", tagVals...))
		}

		rec.AddAttributes(attrs...)
		p.logger.Emit(ctx, rec)
	}
}

func buildScanBody(result *scanner.ScanResult, scanID, targetType string) scanBody {
	findings := make([]scanBodyFinding, len(result.Findings))
	for i, f := range result.Findings {
		findings[i] = scanBodyFinding{
			ID:       f.ID,
			Severity: string(f.Severity),
			Title:    f.Title,
			Scanner:  f.Scanner,
			Tags:     f.Tags,
		}
	}

	return scanBody{
		ScanID:       scanID,
		Scanner:      result.Scanner,
		Target:       result.Target,
		TargetType:   targetType,
		Timestamp:    result.Timestamp.UTC().Format(time.RFC3339),
		DurationMs:   result.Duration.Milliseconds(),
		FindingCount: len(result.Findings),
		MaxSeverity:  string(result.MaxSeverity()),
		Findings:     findings,
	}
}

func scanSeverityToOTel(maxSev string) (string, int) {
	switch maxSev {
	case "CRITICAL":
		return "ERROR", 17
	case "HIGH":
		return "WARN", 13
	default:
		return "INFO", 9
	}
}

func findingSeverityToOTel(sev string) (string, int) {
	switch sev {
	case "CRITICAL":
		return "CRITICAL", 21
	case "HIGH":
		return "HIGH", 17
	case "MEDIUM":
		return "MEDIUM", 13
	case "LOW":
		return "LOW", 9
	default:
		return "INFO", 9
	}
}
