// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// LaunchCoverageReport is a root lifecycle observation of an agent process
// that can run without its managed plugin. It contains no argv or environment.
type LaunchCoverageReport struct {
	Connector string `json:"connector"`
	Reason    string `json:"reason"`
	PID       int    `json:"pid"`
	UID       int    `json:"uid"`
	StartedAt string `json:"started_at"`
	// InstallPath and Version describe a static, runnable copy. Such a
	// report has PID zero and no process start time.
	InstallPath string `json:"install_path,omitempty"`
	Version     string `json:"version,omitempty"`
	// ScanState describes the pending install scan's record (its age, or
	// missing) in a LaunchCoverageScanPending report, which names no
	// connector, user, process or install.
	ScanState string `json:"scan_state,omitempty"`
}

// LaunchCoverageScanPending reports a missing or stale unprotected-agents
// record (GAP-1430).
const LaunchCoverageScanPending = "agent_install_scan_pending"

const LaunchCoverageReportPath = "/api/v1/managed/launch-coverage"
