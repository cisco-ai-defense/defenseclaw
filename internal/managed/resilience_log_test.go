// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

func TestFormatResilienceEventIsStable(t *testing.T) {
	got := FormatResilienceEvent(MarkerRepair, map[string]string{
		"reason": `inherited "Users" write`,
		"path":   `C:\ProgramData\x`,
	})
	want := `defenseclaw_repair path="C:\\ProgramData\\x" reason="inherited \"Users\" write"`
	if got != want {
		t.Fatalf("FormatResilienceEvent = %s, want %s", got, want)
	}
	if got := FormatResilienceEvent(MarkerSkip, nil); got != MarkerSkip {
		t.Fatalf("no fields = %q, want the bare marker", got)
	}
}

func TestEmitResilienceEventUsesSink(t *testing.T) {
	var gotMarker string
	var gotFields map[string]string
	previous := ReportResilienceEvent
	ReportResilienceEvent = func(marker string, fields map[string]string) {
		gotMarker, gotFields = marker, fields
	}
	defer func() { ReportResilienceEvent = previous }()
	EmitResilienceEvent(MarkerDegraded, map[string]string{"subsystem": "api"})
	if gotMarker != MarkerDegraded || gotFields["subsystem"] != "api" {
		t.Fatalf("sink got %q %v", gotMarker, gotFields)
	}
}
