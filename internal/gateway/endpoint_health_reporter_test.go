// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/diagnostics"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func endpointHealthManagedConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: t.TempDir()}
	cfg.CiscoAIDefense.Endpoint = "https://aid.example.test"
	return cfg
}

func TestEndpointHealthReporterEnabledOnlyForManagedSecureClient(t *testing.T) {
	standalone := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	for name, cfg := range map[string]*config.Config{
		"nil":                   nil,
		"oss":                   {},
		"standalone enterprise": standalone,
	} {
		if endpointHealthReporterEnabled(cfg) {
			t.Errorf("%s: reporter enabled", name)
		}
	}
	if !endpointHealthReporterEnabled(endpointHealthManagedConfig(t)) {
		t.Fatal("managed Secure Client: reporter disabled")
	}
}

func TestEndpointHealthNextDelayJitter(t *testing.T) {
	interval := 30 * time.Minute
	for i := 0; i < 200; i++ {
		delay := endpointHealthNextDelay(interval)
		if delay < interval || delay >= interval+interval/10 {
			t.Fatalf("delay %v outside [%v, %v)", delay, interval, interval+interval/10)
		}
	}
	if got := endpointHealthNextDelay(0); got < inventory.ManagedEnterpriseScanInterval {
		t.Fatalf("zero interval delay %v below the managed floor", got)
	}
}

func TestEndpointHealthIntervalFallsBackToManagedFloor(t *testing.T) {
	s := &Sidecar{cfg: endpointHealthManagedConfig(t)}
	if got := s.endpointHealthInterval(); got != inventory.ManagedEnterpriseScanInterval {
		t.Fatalf("interval without discovery = %v", got)
	}
}

func TestEndpointHealthReportIDIsUUIDv4(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id := newEndpointHealthReportID()
		if !pattern.MatchString(id) || seen[id] {
			t.Fatalf("bad or repeated report id %q", id)
		}
		seen[id] = true
	}
}

func TestEndpointHealthSeverityMapping(t *testing.T) {
	for status, want := range map[string][2]string{
		"healthy":   {string(observability.SeverityInfo), string(observability.LogLevelInfo)},
		"starting":  {string(observability.SeverityLow), string(observability.LogLevelInfo)},
		"degraded":  {string(observability.SeverityMedium), string(observability.LogLevelWarn)},
		"unhealthy": {string(observability.SeverityHigh), string(observability.LogLevelError)},
	} {
		severity, level := endpointHealthSeverity(status)
		if string(severity) != want[0] || string(level) != want[1] {
			t.Errorf("%s: got %s/%s, want %s/%s", status, severity, level, want[0], want[1])
		}
	}
}

// The builder input built from a real report must satisfy the registry
// contract, including failing targets with a user id.
func TestEndpointHealthV8InputBuildsValidRecord(t *testing.T) {
	src := healthyEndpointHealthSources()
	src.Guardian.Targets = append(src.Guardian.Targets, endpointHealthGuardianTarget{
		Connector: "codex", UserID: "S-1-5-21-1-2-3-1002", Error: "permission denied writing hooks.json",
	})
	report := buildEndpointHealthReport(src, endpointHealthTestMeta)
	if len(report.HooksFailingTargets) == 0 || report.Status == "healthy" {
		t.Fatalf("fixture did not produce a failing target: %+v", report)
	}
	input := endpointHealthV8Input(report)
	severity, level := endpointHealthSeverity(report.Status)
	input.Severity, input.LogLevel = observability.Present(severity), observability.Present(level)
	input.Envelope = observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Action: string(config.ObservabilityV8ManagedEndpointHealthAction),
		Phase:      "report",
		Provenance: observability.FamilyProvenanceInput{Producer: endpointHealthV8Producer, BinaryVersion: "1.0.9"},
	}
	builder, err := aiDiscoveryV8Builder()
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildLogEndpointHealthReported(input)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if string(record.EventName()) != observability.TelemetryEventEndpointHealthReported {
		t.Fatalf("event name = %q", record.EventName())
	}
}

type endpointHealthCapture struct {
	reports []endpointHealthReport
	files   []diagnostics.HealthReportFileContent
}

func newCapturingEndpointHealthReporter(s *Sidecar, emitErr error) (*endpointHealthReporter, *endpointHealthCapture) {
	capture := &endpointHealthCapture{}
	r := newEndpointHealthReporter(s)
	r.emit = func(_ context.Context, report endpointHealthReport) (endpointHealthEmitResult, error) {
		capture.reports = append(capture.reports, report)
		return endpointHealthEmitResult{routedToManaged: emitErr == nil}, emitErr
	}
	write := r.write
	r.write = func(dataDir string, content diagnostics.HealthReportFileContent) error {
		capture.files = append(capture.files, content)
		return write(dataDir, content)
	}
	return r, capture
}

func TestEndpointHealthReportWritesDiagnosticsFileAndPersistsSequence(t *testing.T) {
	cfg := endpointHealthManagedConfig(t)
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	r, capture := newCapturingEndpointHealthReporter(s, nil)
	r.report(context.Background(), endpointHealthTriggerStartup)
	r.report(context.Background(), endpointHealthTriggerScheduled)
	if len(capture.reports) != 2 {
		t.Fatalf("emitted %d reports", len(capture.reports))
	}
	if capture.reports[0].Sequence != 1 || capture.reports[1].Sequence != 2 ||
		capture.reports[0].Trigger != endpointHealthTriggerStartup || capture.reports[0].ReportID == capture.reports[1].ReportID {
		t.Fatalf("reports: %+v / %+v", capture.reports[0], capture.reports[1])
	}

	raw, err := os.ReadFile(diagnostics.Path(cfg.DataDir, diagnostics.HealthReportFile))
	if err != nil {
		t.Fatal(err)
	}
	var content diagnostics.HealthReportFileContent
	if err := json.Unmarshal(raw, &content); err != nil {
		t.Fatal(err)
	}
	if content.SchemaVersion != diagnostics.HealthReportFileVersion || content.Delivery.Result != "queued" {
		t.Fatalf("file content: %+v", content)
	}

	// A restarted reporter continues the sequence from the file.
	next := newEndpointHealthReporter(s)
	if got := next.loadSequence(); got != 2 {
		t.Fatalf("loaded sequence %d, want 2", got)
	}
}

func TestEndpointHealthReportRecordsEmitFailureWithoutRawText(t *testing.T) {
	s := &Sidecar{cfg: endpointHealthManagedConfig(t), health: NewSidecarHealth()}
	r, capture := newCapturingEndpointHealthReporter(s, errors.New("dial tcp 10.0.0.1: secret detail"))
	r.report(context.Background(), endpointHealthTriggerScheduled)
	if len(capture.files) != 1 {
		t.Fatalf("wrote %d files", len(capture.files))
	}
	delivery := capture.files[0].Delivery
	if delivery.Result != "failed" || delivery.FailureClass != "EMIT_FAILED" {
		t.Fatalf("delivery = %+v", delivery)
	}
}

func TestEndpointHealthReportSendsNothingOutsideManagedSecureClient(t *testing.T) {
	s := &Sidecar{cfg: &config.Config{DataDir: t.TempDir()}, health: NewSidecarHealth()}
	r, capture := newCapturingEndpointHealthReporter(s, nil)
	r.report(context.Background(), endpointHealthTriggerScheduled)
	if len(capture.reports) != 0 || len(capture.files) != 0 {
		t.Fatalf("non-managed reporter emitted %d reports and %d files", len(capture.reports), len(capture.files))
	}
	if _, err := os.Stat(diagnostics.Dir(s.cfg.DataDir)); !os.IsNotExist(err) {
		t.Fatalf("diagnostics folder created: %v", err)
	}
}

func TestEndpointHealthLoadSequenceIgnoresBadFiles(t *testing.T) {
	cfg := endpointHealthManagedConfig(t)
	s := &Sidecar{cfg: cfg}
	r := newEndpointHealthReporter(s)
	if got := r.loadSequence(); got != 0 {
		t.Fatalf("missing file: %d", got)
	}
	if err := os.MkdirAll(diagnostics.Dir(cfg.DataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`garbage`, `{"schema_version":99,"report":{"defenseclaw.health.sequence":5}}`} {
		if err := os.WriteFile(diagnostics.Path(cfg.DataDir, diagnostics.HealthReportFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := r.loadSequence(); got != 0 {
			t.Fatalf("%s: sequence %d", body, got)
		}
	}
}

// A report emitted through a real v8 runtime reaches the generated managed AI
// Defense destination as a platform.health record that keeps its body,
// including the failing target's user id.
func TestEndpointHealthEmitReachesManagedAIDDestination(t *testing.T) {
	runtime, _, adapter := newManagedAIDFailOpenRuntime(t)
	src := healthyEndpointHealthSources()
	src.Guardian.Targets = append(src.Guardian.Targets, endpointHealthGuardianTarget{
		Connector: "codex", UserID: "S-1-5-21-1-2-3-1002", Error: "permission denied writing hooks.json",
	})
	report := buildEndpointHealthReport(src, endpointHealthTestMeta)

	result, err := emitEndpointHealthV8(context.Background(), runtime, report)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !result.routedToManaged {
		t.Fatal("record was not routed to the managed destination")
	}
	var delivered managedAIDFailOpenDelivery
	select {
	case delivered = <-adapter.delivered:
	case <-time.After(10 * time.Second):
		t.Fatal("managed destination received nothing")
	}
	if delivered.identity.Bucket != string(observability.BucketPlatformHealth) ||
		delivered.identity.EventName != observability.TelemetryEventEndpointHealthReported {
		t.Fatalf("identity = %+v", delivered.identity)
	}
	body := string(delivered.bytes)
	for _, want := range []string{
		report.ReportID, "S-1-5-21-1-2-3-1002", "HOOKS_PARTIAL", "5.1.21.4204", "endpoint_health",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("delivered record lacks %q", want)
		}
	}
	if strings.Contains(body, "permission denied") {
		t.Error("delivered record carries raw guardian error text")
	}
}

// Without a Cisco AI Defense endpoint the managed destination, and the drop
// routes that keep the report off operator destinations, are not compiled,
// so the reporter sends nothing.
func TestEndpointHealthReportSendsNothingWithoutAIDefenseEndpoint(t *testing.T) {
	cfg := endpointHealthManagedConfig(t)
	cfg.CiscoAIDefense.Endpoint = "  "
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	r, capture := newCapturingEndpointHealthReporter(s, nil)
	r.report(context.Background(), endpointHealthTriggerScheduled)
	if len(capture.reports) != 0 || len(capture.files) != 0 {
		t.Fatalf("reporter emitted %d reports and %d files without an endpoint", len(capture.reports), len(capture.files))
	}
}

// An undelivered report leaves the "since last report" cursor where the last
// delivered report put it, so its counts reach the next delivered report.
func TestEndpointHealthUndeliveredReportKeepsTheCursor(t *testing.T) {
	s := &Sidecar{cfg: endpointHealthManagedConfig(t), health: NewSidecarHealth()}
	r, _ := newCapturingEndpointHealthReporter(s, errors.New("emit failed"))
	before := endpointHealthCursor{previousReportAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), failOpenTotal: 3, failOpenRead: true}
	r.cursor = before
	r.report(context.Background(), endpointHealthTriggerScheduled)
	if r.cursor != before {
		t.Fatalf("cursor advanced by an undelivered report: %+v", r.cursor)
	}

	delivered, _ := newCapturingEndpointHealthReporter(s, nil)
	delivered.cursor = before
	delivered.report(context.Background(), endpointHealthTriggerScheduled)
	if delivered.cursor.previousReportAt.Equal(before.previousReportAt) {
		t.Fatal("cursor not advanced by a delivered report")
	}
}

func TestEndpointHealthIntervalCappedAtRegistryMaximum(t *testing.T) {
	if got := min(48*time.Hour, endpointHealthMaxInterval); got != 24*time.Hour {
		t.Fatalf("cap = %v", got)
	}
	if endpointHealthMaxInterval.Seconds() != 86400 {
		t.Fatalf("cap %v is not the report_interval_s maximum", endpointHealthMaxInterval)
	}
}
