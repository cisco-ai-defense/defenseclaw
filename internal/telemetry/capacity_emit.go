// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

const exporterErrLogMinInterval = time.Second

var exporterErrLogMu sync.Mutex
var lastExporterErrLog time.Time

func (p *Provider) emitConfigLoadFailure(ctx context.Context, reason string) {
	if p == nil || !p.Enabled() {
		return
	}
	ev := gatewaylog.Event{
		Timestamp: time.Now(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemConfig),
			Code:      string(gatewaylog.ErrCodeConfigLoadFailed),
			Message:   "configuration load or validation failed",
			Cause:     reason,
		},
	}
	p.EmitGatewayEvent(ev)
}

func (p *Provider) emitSQLiteBusy(ctx context.Context, operation string) {
	if p == nil || !p.Enabled() {
		return
	}
	ev := gatewaylog.Event{
		Timestamp: time.Now(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityMedium,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemSQLite),
			Code:      string(gatewaylog.ErrCodeSQLiteBusy),
			Message:   "SQLite returned SQLITE_BUSY",
			Cause:     operation,
		},
	}
	p.EmitGatewayEvent(ev)
}

func (p *Provider) emitPanicRecovered(ctx context.Context, subsystem gatewaylog.Subsystem) {
	if p == nil || !p.Enabled() {
		return
	}
	ev := gatewaylog.Event{
		Timestamp: time.Now(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(subsystem),
			Code:      string(gatewaylog.ErrCodePanicRecovered),
			Message:   "panic recovered",
			Cause:     string(subsystem),
		},
	}
	p.EmitGatewayEvent(ev)
}

// emitExporterFailure records a telemetry export failure with the full
// error reason. Rate-limited to at most one emit per exporterErrLogMinInterval
// so a persistent 401/network outage doesn't flood the gateway.jsonl surface.
//
// The `reason` string carries the actual underlying error text (e.g.
// "cisco ai defense telemetry: ingest HTTP 401: token expired"). Callers
// should pass err.Error() rather than a canned message — this event is
// the operator's primary signal for "why is my telemetry not flowing?"
// and hiding the cause makes triage impossible.
//
// Errors that start with "cisco ai defense telemetry:" are tagged with
// the CiscoAIDLogExport subsystem so consumers can filter for the
// managed AID sink specifically (auth vs network vs ingest 5xx).
func (p *Provider) emitExporterFailure(ctx context.Context, exporter string, reason string) {
	if p == nil || !p.Enabled() {
		return
	}
	exporterErrLogMu.Lock()
	if d := time.Since(lastExporterErrLog); d < exporterErrLogMinInterval {
		exporterErrLogMu.Unlock()
		return
	}
	lastExporterErrLog = time.Now()
	exporterErrLogMu.Unlock()

	subsystem := string(gatewaylog.SubsystemTelemetry)
	message := "OpenTelemetry export failed"
	// The AID log exporter wraps every error with a stable prefix; use
	// it to route failures to a dedicated subsystem so operators can
	// alert on managed-sink-specific breakage.
	if strings.HasPrefix(reason, "cisco ai defense telemetry:") {
		subsystem = string(gatewaylog.SubsystemCiscoAIDExport)
		message = "Cisco AI Defense telemetry export failed"
	}
	cause := reason
	if cause == "" {
		cause = exporter
	} else if exporter != "" && !strings.Contains(cause, exporter) {
		cause = exporter + ": " + cause
	}
	ev := gatewaylog.Event{
		Timestamp: time.Now(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityMedium,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: subsystem,
			Code:      string(gatewaylog.ErrCodeExportFailed),
			Message:   message,
			Cause:     cause,
		},
	}
	p.EmitGatewayEvent(ev)
}
