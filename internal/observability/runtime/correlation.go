// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// correlationDefaultMode distinguishes locally generated records from native
// OTLP imports. A receiver request's transport correlation is not the native
// record's business identity, so imported records inherit only the three
// occurrence-coordinator IDs. Connector-specific native session, turn, model,
// tool, trace, and span IDs are mapped by the inbound profile/builder and stay
// authoritative on the record.
type correlationDefaultMode uint8

const (
	correlationDefaultsGenerated correlationDefaultMode = iota
	correlationDefaultsGeneratedTrace
	correlationDefaultsImported
)

var errRuntimeCorrelationIncomplete = errors.New("observability runtime correlation envelope is incomplete")

func correlationDefaultsFromContext(
	ctx context.Context,
	mode correlationDefaultMode,
) observability.Correlation {
	envelope := audit.EnvelopeFromContext(ctx)
	defaults := observability.Correlation{
		SemanticEventID:     envelope.SemanticEventID,
		LogicalEventID:      envelope.LogicalEventID,
		ConnectorInstanceID: envelope.ConnectorInstanceID,
	}
	if mode == correlationDefaultsImported {
		return defaults
	}
	defaults.RunID = envelope.RunID
	defaults.RequestID = envelope.RequestID
	defaults.SessionID = envelope.SessionID
	defaults.TurnID = envelope.TurnID
	defaults.AgentID = envelope.AgentID
	defaults.AgentInstanceID = envelope.AgentInstanceID
	defaults.PolicyID = envelope.PolicyID
	defaults.ToolInvocationID = envelope.ToolID
	defaults.ConnectorID = envelope.Connector
	defaults.SidecarInstanceID = envelope.SidecarInstanceID
	// Generated physical spans seal their own topology. Request-context
	// trace identity remains useful for generated logs and metric exemplars,
	// but must never replace or conflict with the actual span context.
	if mode != correlationDefaultsGeneratedTrace {
		defaults.TraceID = envelope.TraceID
	}
	return defaults
}

func stampRuntimeCorrelation(
	record observability.Record,
	defaults observability.Correlation,
) (observability.Record, error) {
	return record.WithCorrelationDefaults(defaults)
}

// persistRuntimeCorrelationObservation is the commit-before-export boundary
// for traces and metrics. It stores correlation metadata only: no trace body,
// metric value, labels, prompt, tool arguments, or result content enters the
// ledger. Logs use EventHistoryWriter's caller-owned transaction so their
// canonical local projection and observation commit atomically.
func persistRuntimeCorrelationObservation(
	ctx context.Context,
	store *audit.Store,
	record observability.Record,
) error {
	correlation := record.Correlation()
	if correlation.SemanticEventID == "" && correlation.LogicalEventID == "" &&
		correlation.ConnectorInstanceID == "" {
		return nil
	}
	if correlation.SemanticEventID == "" || correlation.LogicalEventID == "" ||
		correlation.ConnectorInstanceID == "" || store == nil {
		return errRuntimeCorrelationIncomplete
	}
	repository, err := store.CorrelationRepository()
	if err != nil {
		return err
	}
	observation, err := runtimeCorrelationObservation(record)
	if err != nil {
		return err
	}
	return repository.RecordObservation(ctx, observation)
}

func runtimeCorrelationObservation(record observability.Record) (audit.CorrelationObservation, error) {
	correlation := record.Correlation()
	signal, ok := runtimeCorrelationSignal(record.Signal())
	if !ok {
		return audit.CorrelationObservation{}, errRuntimeCorrelationIncomplete
	}
	lifecycleID, executionID := runtimeLifecycleAndExecution(record)
	return audit.CorrelationObservation{
		RecordID: record.RecordID(), SemanticEventID: audit.SemanticEventID(correlation.SemanticEventID),
		Signal: signal, Bucket: string(record.Bucket()), EventName: string(record.EventName()),
		ObservedAt: time.Now().UTC(), TraceID: correlation.TraceID, SpanID: correlation.SpanID,
		SessionID: correlation.SessionID, TurnID: correlation.TurnID, AgentID: correlation.AgentID,
		LifecycleID: lifecycleID, ExecutionID: executionID,
		ModelRequestID: correlation.ModelRequestID, ModelResponseID: correlation.ModelResponseID,
		ToolInvocationID: correlation.ToolInvocationID,
		Status:           audit.CorrelationObservationExportEligible,
	}, nil
}

func runtimeCorrelationSignal(signal observability.Signal) (audit.CorrelationSignal, bool) {
	switch signal {
	case observability.SignalLogs:
		return audit.CorrelationSignalLogs, true
	case observability.SignalTraces:
		return audit.CorrelationSignalTraces, true
	case observability.SignalMetrics:
		return audit.CorrelationSignalMetrics, true
	default:
		return "", false
	}
}

// Lifecycle and execution remain registered telemetry fields rather than
// generic Correlation members. Read only those two exact, bounded attributes;
// never retain or inspect content fields while producing ledger metadata.
func runtimeLifecycleAndExecution(record observability.Record) (string, string) {
	if data, ok := record.InstrumentData(); ok {
		if object, err := data.Object(); err == nil {
			if lifecycle, execution, found := runtimeLifecycleAndExecutionAttributes(object); found {
				return lifecycle, execution
			}
		}
	}
	if body, ok := record.Body(); ok {
		if object, err := body.Object(); err == nil {
			if lifecycle, execution, found := runtimeLifecycleAndExecutionAttributes(object); found {
				return lifecycle, execution
			}
		}
	}
	return "", ""
}

func runtimeLifecycleAndExecutionAttributes(object map[string]any) (string, string, bool) {
	attributes := object
	if nested, ok := object["attributes"].(map[string]any); ok {
		attributes = nested
	}
	lifecycle, _ := attributes["defenseclaw.agent.lifecycle.id"].(string)
	execution, _ := attributes["defenseclaw.agent.execution.id"].(string)
	return lifecycle, execution, lifecycle != "" || execution != ""
}
