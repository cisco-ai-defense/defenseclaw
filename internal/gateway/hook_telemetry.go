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

package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func normalizeHookTelemetryLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func (a *APIServer) recordConnectorHookRejection(ctx context.Context, connectorName, eventType, reason string, bodyBytes int64) {
	connectorName = normalizeHookTelemetryLabel(connectorName, "unknown")
	eventType = normalizeHookTelemetryLabel(eventType, "unknown")
	reason = normalizeHookTelemetryLabel(reason, "unknown")

	if a.otel != nil {
		a.otel.RecordConnectorHookInvocation(ctx, connectorName, eventType, "rejected", reason, 0)
		a.otel.EmitConnectorTelemetryLog(ctx, "hook", connectorName, "rejected", 0, bodyBytes,
			fmt.Sprintf("source=hook connector=%s event=%s result=rejected reason=%s bytes=%d",
				connectorName, eventType, reason, bodyBytes))
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(ctx, string(audit.ActionConnectorHook), eventType,
			fmt.Sprintf("connector=%s result=rejected reason=%s bytes=%d", connectorName, reason, bodyBytes))
	}
}

func (a *APIServer) logConnectorHookAudit(ctx context.Context, connectorName, eventType, details string) {
	if a.logger == nil {
		return
	}
	connectorName = normalizeHookTelemetryLabel(connectorName, "unknown")
	eventType = normalizeHookTelemetryLabel(eventType, "unknown")
	if strings.TrimSpace(details) == "" {
		details = "result=ok"
	}
	_ = a.logger.LogActionCtx(ctx, string(audit.ActionConnectorHook), eventType,
		fmt.Sprintf("connector=%s %s", connectorName, details))
}

func (a *APIServer) logAssetPolicyAudit(ctx context.Context, target, details string) {
	if a.logger == nil {
		return
	}
	_ = a.logger.LogActionCtx(ctx, string(audit.ActionAssetPolicy), target, details)
}
