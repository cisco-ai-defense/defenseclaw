// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedHookDecisionEventID tags managed hook decisions in the Application
// event log; the gateway service itself uses 1 (degraded) and 2 (log line).
const managedHookDecisionEventID = 3

// writeManagedHookDecisionRecord appends line to the Windows Application
// event log under the gateway service's existing event source. Interactive
// and service accounts may write the Application log without any grant of
// their own, the log is size-capped and rotated by Windows, and support
// bundles already collect that source. Best-effort: a failure never changes
// the hook's decision.
func writeManagedHookDecisionRecord(source, marker, line string) {
	events, err := eventlog.Open(source)
	if err != nil {
		return
	}
	defer events.Close()
	if marker == managed.MarkerBoundary {
		_ = events.Error(managedHookDecisionEventID, line)
		return
	}
	_ = events.Warning(managedHookDecisionEventID, line)
}

// managedHookDecisionRecordSource is the protected gateway service name when
// the hook has one, so certification-scoped installs keep their own source,
// and the production gateway source otherwise.
func managedHookDecisionRecordSource(serviceName string) string {
	if validateManagedGatewayServiceName(serviceName) != nil {
		return managedHookDecisionRecordDefaultSource
	}
	return serviceName
}
