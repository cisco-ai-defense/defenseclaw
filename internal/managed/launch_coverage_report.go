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
}

const LaunchCoverageReportPath = "/api/v1/managed/launch-coverage"
