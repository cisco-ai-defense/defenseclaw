// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"strings"
	"testing"
)

func capturePrereqEvents(t *testing.T) *[]string {
	t.Helper()
	var events []string
	previous := ReportResilienceEvent
	ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() { ReportResilienceEvent = previous })
	return &events
}

func TestPrereqReporterLogsOncePerStreak(t *testing.T) {
	events := capturePrereqEvents(t)
	var reporter PrereqReporter
	finding := PrereqFinding{Check: PrereqHookTransportTools, Path: "jq", Remedy: "install jq"}

	reporter.Report([]PrereqFinding{finding})
	reporter.Report([]PrereqFinding{finding})
	if len(*events) != 1 || !strings.HasPrefix((*events)[0], `defenseclaw_prereq check="hook_transport_tools"`) {
		t.Fatalf("events = %v, want one prereq line", *events)
	}
	if !strings.Contains((*events)[0], `remedy="install jq"`) {
		t.Fatalf("prereq line lacks the remedy: %s", (*events)[0])
	}
	reporter.Report(nil)
	reporter.Report([]PrereqFinding{finding})
	if len(*events) != 2 {
		t.Fatalf("a new streak was not logged: %v", *events)
	}
}

func TestCMIDLibraryLoadFindingMatchesOnlyCodeSigningRefusals(t *testing.T) {
	refusals := []string{
		"dlopen(/opt/cisco/secureclient/lib/libcmidapi.dylib, 0x0001): tried: '/x' (code signature in <ABC> '/x' not valid for use in process: mapping process and mapped file (non-platform) have different Team IDs)",
		"dlopen(libcmidapi.dylib): library load disallowed by system policy",
	}
	for _, message := range refusals {
		if _, ok := CMIDLibraryLoadFinding(errors.New(message)); !ok {
			t.Fatalf("refusal not classified: %s", message)
		}
	}
	for _, message := range []string{"dlopen(libcmidapi.dylib): image not found", "connection refused"} {
		if _, ok := CMIDLibraryLoadFinding(errors.New(message)); ok {
			t.Fatalf("non-policy error classified as a prerequisite: %s", message)
		}
	}
}

func TestReportCMIDLibraryLoadErrorLogsOncePerStreak(t *testing.T) {
	events := capturePrereqEvents(t)
	refusal := errors.New("library load disallowed by system policy")
	ReportCMIDLibraryLoadError(nil)
	ReportCMIDLibraryLoadError(refusal)
	ReportCMIDLibraryLoadError(refusal)
	if len(*events) != 1 || !strings.Contains((*events)[0], PrereqCMIDLibraryValidation) {
		t.Fatalf("events = %v, want one cmid_library_validation line", *events)
	}
	ReportCMIDLibraryLoadError(nil)
	ReportCMIDLibraryLoadError(refusal)
	if len(*events) != 2 {
		t.Fatalf("a new streak after a successful load was not logged: %v", *events)
	}
	ReportCMIDLibraryLoadError(nil)
}
