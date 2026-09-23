// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestEndpointSecurityControlRequestCompletionChain(t *testing.T) {
	t.Parallel()
	guid := `{2E1864BB-1534-629F-1004-000000006002}`
	request := EvaluateDeterministicAction(context.Background(), actionfacts.Input{
		Tool: "shell", DialectHint: actionfacts.DialectCMD,
		Command: `reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f`,
		Args:    json.RawMessage(`{"event_id":"1","process_guid":"` + guid + `","process_image":"C:\\Windows\\System32\\reg.exe","provider":"Microsoft-Windows-Sysmon"}`),
	}, "", "", "default")
	completion := EvaluateDeterministicAction(context.Background(), actionfacts.Input{
		Tool: "windows.event",
		Args: json.RawMessage(`{"details":"DWORD (0x00000000)","event_id":"13","operation":"SetValue","process_guid":"` + guid + `","provider":"Microsoft-Windows-Sysmon","resource":"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\\Start"}`),
	}, "", "", "default")
	definition, ok := guardrail.ToolChainDefinitionByID(guardrail.ToolChainEndpointSecurityControlMutation)
	index, indexOK := guardrail.ToolChainIndexByID(guardrail.ToolChainEndpointSecurityControlMutation)
	if !ok || !indexOK || request.DetectionStepMask&definition.Step1Bit == 0 ||
		completion.DetectionStepMask&definition.Step2Bit == 0 ||
		request.EnforcementJoinDigests[index] == "" ||
		request.EnforcementJoinDigests[index] != completion.EnforcementJoinDigests[index] {
		t.Fatalf("request=%+v completion=%+v definition=%+v", request, completion, definition)
	}
	now := time.Now().UTC()
	matches, err := guardrail.MatchToolChains([]guardrail.ToolChainWindowEvent{{
		SemanticEventID: "request", Sequence: 1, ReceivedAt: now,
		Projection: guardrail.ToolChainProjection{
			ParseStatus: requestParseStatus(request.ParseStatus), DetectionStepMask: request.DetectionStepMask,
			EnforcementStepMask: request.EnforcementStepMask, EnforcementJoinDigests: request.EnforcementJoinDigests,
		},
	}}, guardrail.ToolChainWindowEvent{
		SemanticEventID: "completion", Sequence: 2, ReceivedAt: now.Add(time.Second),
		Projection: guardrail.ToolChainProjection{
			ParseStatus: requestParseStatus(completion.ParseStatus), DetectionStepMask: completion.DetectionStepMask,
			EnforcementStepMask: completion.EnforcementStepMask, EnforcementJoinDigests: completion.EnforcementJoinDigests,
		},
	})
	if err != nil || matches.DetectedMask&definition.ResultBit == 0 || matches.EnforcementSafeMask != 0 {
		t.Fatalf("matches=%+v err=%v", matches, err)
	}
}

func requestParseStatus(value string) actionfacts.ParseStatus { return actionfacts.ParseStatus(value) }
