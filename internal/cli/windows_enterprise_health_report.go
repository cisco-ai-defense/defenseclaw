// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsSecureClientHealthReportKey is the member the Secure Client status
// document gains when the gateway has written a health report.
const windowsSecureClientHealthReportKey = "health_report"

// injectWindowsSecureClientHealthReport adds a "health_report" member to the
// installer's status document in body (the last top-level JSON object, the
// one the JSON relay prints) and returns the new bytes. Every other byte is
// kept as it is. body is returned unchanged when state is nil, when there is
// no status document (a preflight failure object has no "installed"), or
// when the document already has the member.
func injectWindowsSecureClientHealthReport(body []byte, state *enterprisestatus.HealthReportState) []byte {
	if state == nil {
		return body
	}
	start, end, ok := lastWindowsEnterpriseJSONObjectSpan(body)
	if !ok {
		return body
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body[start:end], &members); err != nil {
		return body
	}
	if _, isStatus := members["installed"]; !isStatus {
		return body
	}
	if _, present := members[windowsSecureClientHealthReportKey]; present {
		return body
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return body
	}
	// The object ends with '}'; insert before it, after the last member.
	closing := end - 1
	insertAt := len(bytes.TrimRight(body[start:closing], " \t\r\n")) + start
	out := make([]byte, 0, len(body)+len(encoded)+len(windowsSecureClientHealthReportKey)+4)
	out = append(out, body[:insertAt]...)
	out = append(out, `,"`+windowsSecureClientHealthReportKey+`":`...)
	out = append(out, encoded...)
	out = append(out, body[insertAt:]...)
	return out
}
