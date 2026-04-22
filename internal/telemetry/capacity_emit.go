// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
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

func (p *Provider) emitExporterFailure(ctx context.Context, exporter string) {
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

	ev := gatewaylog.Event{
		Timestamp: time.Now(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityMedium,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemTelemetry),
			Code:      string(gatewaylog.ErrCodeExportFailed),
			Message:   "OpenTelemetry metric export failed",
			Cause:     exporter,
		},
	}
	p.EmitGatewayEvent(ev)
}
