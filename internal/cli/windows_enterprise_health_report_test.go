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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func testWindowsHealthReportState() *enterprisestatus.HealthReportState {
	return &enterprisestatus.HealthReportState{
		Status: "degraded", ObservedAt: "2026-11-12T11:30:00Z", Sequence: 7, Trigger: "scheduled",
		ReasonCodes: []string{"HOOKS_PARTIAL"},
		Delivery:    &enterprisestatus.HealthReportDelivery{Result: "queued", At: "2026-11-12T11:30:01Z"},
	}
}

// The installer's status document gains one health_report member before its
// closing brace; every other byte is the installer's.
func TestInjectWindowsSecureClientHealthReport(t *testing.T) {
	const document = `{"schema_version":1,"ok":true,"action":"status","installed":true,"errors":[]}` + "\n"
	got := injectWindowsSecureClientHealthReport([]byte(document), testWindowsHealthReportState())
	want := `{"schema_version":1,"ok":true,"action":"status","installed":true,"errors":[],` +
		`"health_report":{"status":"degraded","observed_at":"2026-11-12T11:30:00Z","sequence":7,"trigger":"scheduled",` +
		`"reason_codes":["HOOKS_PARTIAL"],"delivery":{"result":"queued","at":"2026-11-12T11:30:01Z"},"stale":false}}` + "\n"
	if string(got) != want {
		t.Fatalf("injected document:\n%s\nwant:\n%s", got, want)
	}

	pretty := "{\n  \"installed\": false\n}\n"
	got = injectWindowsSecureClientHealthReport([]byte(pretty), &enterprisestatus.HealthReportState{Error: "invalid"})
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(got, &decoded); err != nil || string(decoded["health_report"]) != `{"stale":false,"error":"invalid"}` {
		t.Fatalf("indented document became %s (%v)", got, err)
	}
}

func TestInjectWindowsSecureClientHealthReportLeavesOtherOutput(t *testing.T) {
	state := testWindowsHealthReportState()
	for name, body := range map[string]string{
		"preflight failure": `{"schema_version":1,"ok":false,"action":"status","error":"x","errors":["x"]}` + "\n",
		"already present":   `{"installed":true,"health_report":{"stale":false}}` + "\n",
		"no json":           "DefenseClaw Windows enterprise status: OK\n",
		"empty":             "",
	} {
		if got := injectWindowsSecureClientHealthReport([]byte(body), state); !bytes.Equal(got, []byte(body)) {
			t.Errorf("%s: output changed to %s", name, got)
		}
	}
	body := `{"installed":true}`
	if got := injectWindowsSecureClientHealthReport([]byte(body), nil); string(got) != body {
		t.Errorf("a nil state changed the document to %s", got)
	}
}
