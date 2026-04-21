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
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// capturedLogExporter is an in-memory log.Exporter used to inspect the
// records DefenseClaw emits. Concurrency-safe so it can be shared with the
// BatchProcessor that the SDK uses.
type capturedLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (c *capturedLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, records...)
	return nil
}

func (c *capturedLogExporter) Shutdown(context.Context) error { return nil }
func (c *capturedLogExporter) ForceFlush(context.Context) error {
	return nil
}

func (c *capturedLogExporter) snapshot() []sdklog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]sdklog.Record, len(c.records))
	copy(out, c.records)
	return out
}

// newProviderWithLogCapture returns a Provider whose logger emits into the
// returned capturedLogExporter. The LogsEnabled() path is active.
func newProviderWithLogCapture(t *testing.T) (*Provider, *capturedLogExporter) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}

	// Wire a real LoggerProvider (with a SimpleProcessor for deterministic
	// export) on top of the provider so we can assert on emitted records.
	exp := &capturedLogExporter{}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)
	p.loggerProvider = lp
	p.logger = lp.Logger("test")

	t.Cleanup(func() {
		_ = lp.Shutdown(context.Background())
		_ = p.Shutdown(context.Background())
	})

	return p, exp
}

// attrValue returns the string value for the named attribute, or ""
// when absent / non-string.
func attrValue(r sdklog.Record, key string) string {
	var out string
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == key {
			if kv.Value.Kind() == otellog.KindString {
				out = kv.Value.AsString()
			}
			return false
		}
		return true
	})
	return out
}

// --- PII Redaction Tests ----------------------------------------------------

// piiSecret is a realistic Anthropic API key shape that all PII detectors
// should scrub. Using a real detector-visible pattern ensures we don't
// accidentally test redaction logic that never runs.
const piiSecret = "sk-ant-api03-abcdefghij1234567890abcdefghij1234567890"
const piiSSN = "123-45-6789"

func requireNoSecret(t *testing.T, got, label string) {
	t.Helper()
	if strings.Contains(got, piiSecret) {
		t.Fatalf("%s leaked secret: %q", label, got)
	}
	if strings.Contains(got, piiSSN) {
		t.Fatalf("%s leaked SSN: %q", label, got)
	}
}

func TestEmitPolicyDecision_RedactsReasonAndExtras(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)

	reason := "SEC-ANTHROPIC: blocked secret " + piiSecret
	extra := map[string]string{
		"matched_literal": "user SSN " + piiSSN,
		"rule_name":       "block-anthropic-keys",
	}
	p.EmitPolicyDecision("admission", "blocked", "bad-skill", "skill", reason, extra)

	recs := exp.snapshot()
	if len(recs) != 1 {
		t.Fatalf("expected 1 log record, got %d", len(recs))
	}
	rec := recs[0]

	gotReason := attrValue(rec, "defenseclaw.policy.reason")
	requireNoSecret(t, gotReason, "policy.reason")
	if !strings.Contains(gotReason, "SEC-ANTHROPIC") {
		t.Errorf("expected rule id preserved in reason, got %q", gotReason)
	}

	// extras get ForSinkString applied
	gotMatched := attrValue(rec, "defenseclaw.policy.matched_literal")
	requireNoSecret(t, gotMatched, "policy.matched_literal")

	// body is composed from fixed strings, doesn't include reason
	body := ""
	if rec.Body().Kind() == otellog.KindString {
		body = rec.Body().AsString()
	}
	requireNoSecret(t, body, "policy body")
}

func TestEmitPolicyDecision_IgnoresRevealFlag(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	p, exp := newProviderWithLogCapture(t)

	reason := "SEC-AWS-KEY: token AKIAIOSFODNN7EXAMPLE leaked for user " + piiSSN
	p.EmitPolicyDecision("firewall", "deny", "evil.com", "network", reason, nil)

	recs := exp.snapshot()
	if len(recs) != 1 {
		t.Fatalf("expected 1 log record, got %d", len(recs))
	}
	gotReason := attrValue(recs[0], "defenseclaw.policy.reason")
	if strings.Contains(gotReason, piiSSN) {
		t.Fatalf("reveal flag MUST NOT unmask persistent sink; got %q", gotReason)
	}
	if strings.Contains(gotReason, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("reveal flag MUST NOT unmask AWS key in OTel; got %q", gotReason)
	}
}

func TestEmitRuntimeAlert_RedactsBody(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)

	body := "SEC-ANTHROPIC: detected " + piiSecret + " in outbound prompt"
	p.EmitRuntimeAlert(
		AlertGuardrailBlock, "HIGH", SourceLocalGuardrail, body,
		map[string]string{"tool": "message", "command": "/bin/ls -la"},
		map[string]string{"scanner": "regex", "policy": "secrets", "action_taken": "block"},
		"", "",
	)

	recs := exp.snapshot()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	got := ""
	if recs[0].Body().Kind() == otellog.KindString {
		got = recs[0].Body().AsString()
	}
	requireNoSecret(t, got, "alert body")
	if !strings.Contains(got, "SEC-ANTHROPIC") {
		t.Errorf("rule id dropped from alert body: %q", got)
	}
}

func TestEmitScanResult_RedactsFindingDescriptionAndLocation(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)
	// Force individual-finding emission so description/location attrs
	// are populated; the scan summary body only carries metadata.
	p.cfg.Logs.EmitIndividualFindings = true

	result := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/home/alice/project/main.go",
		Timestamp: time.Now(),
		Duration:  10 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "f1",
				Severity:    "HIGH",
				Title:       "Anthropic API key detected",
				Description: "Matched secret " + piiSecret + " in commit",
				Scanner:     "codeguard",
				Location:    "/home/alice/project/src/leaked.go:42:API_KEY=" + piiSecret,
			},
		},
	}

	p.EmitScanResult(result, "scan-test", "repo", "blocked")

	recs := exp.snapshot()
	if len(recs) < 2 {
		t.Fatalf("expected scan summary + >=1 finding record, got %d", len(recs))
	}

	var findingRec *sdklog.Record
	for i := range recs {
		if attrValue(recs[i], "event.name") == "scan.finding" {
			findingRec = &recs[i]
			break
		}
	}
	if findingRec == nil {
		t.Fatalf("scan.finding record not emitted")
	}

	loc := attrValue(*findingRec, "defenseclaw.finding.location")
	requireNoSecret(t, loc, "finding.location")

	body := ""
	if findingRec.Body().Kind() == otellog.KindString {
		body = findingRec.Body().AsString()
	}
	requireNoSecret(t, body, "finding body")
	if !strings.Contains(body, "Anthropic API key detected") {
		t.Errorf("finding title must be preserved: body=%q", body)
	}
}
