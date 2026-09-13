// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestEndpointSecurityControlMutations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
		want EndpointSecurityControlMutation
	}{
		{"defender exclusion consequence", `{"event_id":"5007","new_value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp\\3 = 0x0","provider":"Microsoft-Windows-Windows Defender"}`, EndpointDefenderExclusionAdded},
		{"defender exclusion registry", `{"details":"0","event_id":"13","operation":"SetValue","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\temp\\"}`, EndpointDefenderExclusionAdded},
		{"defender logger disabled", `{"details":"DWORD (0x00000000)","event_id":"13","operation":"SetValue","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\\Start"}`, EndpointDefenderLoggingDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "windows.event", Args: json.RawMessage(tc.raw)})
			got := ExactEndpointSecurityControlMutations(facts)
			if !facts.Authoritative() || len(got) != 1 || got[0].Operation != tc.want {
				t.Fatalf("parse=%+v facts=%+v", facts.Parse, got)
			}
			if projected := facts.EnforcementProjection().EndpointSecurityControlMutations; len(projected) != 0 {
				t.Fatalf("post-action fact entered enforcement: %+v", projected)
			}
		})
	}
}

func TestEndpointSecurityControlMutationsRejectNearMisses(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"event_id":"5007","new_value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp\\3 = 0x1","provider":"Microsoft-Windows-Windows Defender"}`,
		`{"details":"DWORD (0x00000001)","event_id":"13","operation":"SetValue","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\\Start"}`,
		`{"details":"DWORD (0x00000000)","event_id":"13","operation":"SetValue","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\Software\\Ordinary\\Start"}`,
		`{"details":"0","event_id":"13","operation":"SetValue","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\temp\\","unknown":"value"}`,
	} {
		facts := Analyze(Input{Tool: "windows.event", Args: json.RawMessage(raw)})
		if got := ExactEndpointSecurityControlMutations(facts); len(got) != 0 {
			t.Fatalf("near miss projected: %+v", got)
		}
	}
}

func TestEndpointSecurityControlRequestCompletionLineage(t *testing.T) {
	t.Parallel()
	guid := `{2E1864BB-1534-629F-1004-000000006002}`
	request := Analyze(Input{
		Tool: "shell", DialectHint: DialectCMD,
		Command: `reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f`,
		Args:    json.RawMessage(`{"event_id":"1","process_guid":"` + guid + `","process_image":"C:\\Windows\\System32\\reg.exe","provider":"Microsoft-Windows-Sysmon"}`),
	})
	completion := Analyze(Input{Tool: "windows.event", Args: json.RawMessage(
		`{"details":"DWORD (0x00000000)","event_id":"13","operation":"SetValue","process_guid":"` + guid + `","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\\Start"}`,
	)})
	requestOperation, requestDigest, requestOK := ExactEndpointSecurityControlLineageOperation(request)
	completionOperation, completionDigest, completionOK := ExactEndpointSecurityControlLineageOperation(completion)
	if !requestOK || !completionOK || requestOperation != EndpointDefenderLoggingDisableRequested ||
		completionOperation != EndpointDefenderLoggingDisabled || requestDigest == "" || requestDigest != completionDigest {
		t.Fatalf("request=(%s,%q,%t) completion=(%s,%q,%t) request_parse=%+v", requestOperation, requestDigest, requestOK, completionOperation, completionDigest, completionOK, request.Parse)
	}
}
