// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

// AgentIdentity mirrors gatewaylog.Event three-tier identity fields
// used for scan correlation (gateway package cannot be imported from
// scanner without an import cycle). It also carries the per-request
// correlation IDs (run/session/trace/request) so EmitScanResult can
// stamp them on EventScan / EventScanFinding envelopes and on the
// scan_results / scan_findings rows. Downstream analytics pivot on
// these IDs, so omitting them on the scanner surface would fragment
// per-session aggregates just like the v6 identity bug did.
type AgentIdentity struct {
	AgentID           string
	AgentName         string
	AgentType         string
	AgentInstanceID   string
	SidecarInstanceID string

	RunID     string
	RequestID string
	SessionID string
	TraceID   string
}
