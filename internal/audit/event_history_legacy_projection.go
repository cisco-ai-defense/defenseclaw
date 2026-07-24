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
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type legacyEventProjectionContextKey struct{}

// contextWithLegacyEventProjection carries source compatibility columns into
// EventHistoryWriter. The same canonical runtime transaction can populate the
// historical SQLite columns without inserting a second audit_events row. No
// redaction occurs here; the route-selected central projection remains the
// only privacy boundary.
func contextWithLegacyEventProjection(ctx context.Context, event Event) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	event.Structured = cloneStructuredPayload(event.Structured)
	return context.WithValue(ctx, legacyEventProjectionContextKey{}, event)
}

func legacyEventProjectionFromContext(
	ctx context.Context,
	record observability.Record,
) (Event, bool, error) {
	if ctx == nil {
		return Event{}, false, nil
	}
	// AdmissionFloor is an authenticated, minimal, content-free persistence
	// path. Restoring legacy target/details/structured fields after routing
	// would bypass collection disablement and leak the ordinary occurrence.
	if record.IsFloorOnly() {
		return Event{}, false, nil
	}
	event, ok := ctx.Value(legacyEventProjectionContextKey{}).(Event)
	if !ok {
		return Event{}, false, nil
	}
	// Only compatibility-only generated identities may populate historical
	// columns from their source Event. Schema-derived families are projected by
	// the central redaction engine; restoring their raw source values here would
	// bypass the selected profile after routing.
	if record.SchemaDerivedFieldClasses() ||
		!strings.HasPrefix(string(record.EventName()), "legacy.audit.") {
		return Event{}, false, nil
	}
	correlation := record.Correlation()
	if event.ID != record.RecordID() || !event.Timestamp.UTC().Equal(record.Timestamp()) ||
		event.Action != record.Action() || event.RunID != correlation.RunID ||
		event.TraceID != correlation.TraceID || event.SpanID != correlation.SpanID ||
		event.RequestID != correlation.RequestID ||
		event.SessionID != correlation.SessionID || event.TurnID != correlation.TurnID ||
		event.AgentID != correlation.AgentID || event.AgentInstanceID != correlation.AgentInstanceID ||
		event.PolicyID != correlation.PolicyID || event.Connector != correlation.ConnectorID ||
		event.EvaluationID != correlation.EvaluationID || event.ScanID != correlation.ScanID ||
		event.FindingOccurrenceID != correlation.FindingOccurrenceID ||
		event.SidecarInstanceID != correlation.SidecarInstanceID {
		return Event{}, false, fmt.Errorf("audit: legacy event projection does not match canonical record")
	}
	event.Structured = cloneStructuredPayload(event.Structured)
	return event, true, nil
}
