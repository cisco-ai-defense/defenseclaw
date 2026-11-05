// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package plane

import "fmt"

// bufferDropLimitation names the events a source's buffer dropped, as the
// ENOBUFS loss is named: reduced coverage, never a silence. The Linux
// sources (GAP-0071) and the macOS source (GAP-0072) report it.
func bufferDropLimitation(dropped int64) string {
	return fmt.Sprintf("%d events were dropped from the sensor's event buffer under back-pressure "+
		"(file events first; process events displaced the oldest)", dropped)
}
