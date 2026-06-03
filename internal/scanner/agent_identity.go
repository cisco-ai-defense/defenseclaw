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

	// EvaluationID is an optional join key set by runtime
	// finding emitters (hook handlers, /api/v1/inspect/*, proxy
	// guardrail, mid-stream, tool-call-inspect, watcher rescan)
	// so the per-finding rows produced by EmitScanResult can be
	// correlated back to the upstream evaluation row. Classic
	// scanner-invocation paths (skill, mcp, plugin, aibom,
	// codeguard CLI/file scans) leave it empty.
	EvaluationID string

	// Connector is the originating connector (codex, claudecode, …) when
	// the scan was triggered in a connector-scoped context, so EmitScanResult
	// can attribute scan-finding metrics per connector. Empty for
	// connector-agnostic scans (CLI file scans, background rescans), which
	// record connector="unknown".
	Connector string
}
