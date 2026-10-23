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
}

const LaunchCoverageReportPath = "/api/v1/managed/launch-coverage"
