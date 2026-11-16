// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"fmt"
	"io"
	"strings"
)

// CoworkVMSensorState reports host delivery only. Claude Desktop's diagnostic
// report is required to establish acceptance and execution inside its VM.
type CoworkVMSensorState struct {
	Enabled       bool     `json:"enabled"`
	HostReady     bool     `json:"host_ready"`
	SettingsReady bool     `json:"settings_ready"`
	PackagePath   string   `json:"package_path,omitempty"`
	ReasonCodes   []string `json:"reason_codes,omitempty"`
}

// WriteCoworkVMSensor renders the same host-delivery row on every platform.
func WriteCoworkVMSensor(w io.Writer, s *CoworkVMSensorState) {
	if s == nil {
		return
	}
	if !s.Enabled {
		fmt.Fprintln(w, "  Cowork VM sensor: off")
		return
	}
	fmt.Fprintf(w, "  Cowork VM sensor: host_ready=%v settings_ready=%v", s.HostReady, s.SettingsReady)
	if len(s.ReasonCodes) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(s.ReasonCodes, ", "))
	}
	fmt.Fprintln(w)
}
