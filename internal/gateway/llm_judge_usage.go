// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
)

// processModelUsage is the process model usage engine, set once by the
// sidecar. Calls the gateway makes itself (judge, decision model, AI Defense)
// record through it; with none set (unit tests) they record nothing.
var processModelUsage atomic.Pointer[modelusage.Engine]

func processUsageRecorder() modelusage.Recorder {
	if e := processModelUsage.Load(); e != nil {
		return e
	}
	return modelusage.Noop
}

// beginJudgeUsage starts the usage record of one judge LLM call. The judge
// is not an agent connector: the record is attributed to the gateway and
// carries role judge and the judge kind (injection, pii, tool) as surface.
func (j *LLMJudge) beginJudgeUsage(ctx context.Context, kind string) modelusage.Call {
	return processUsageRecorder().Begin(ctx, modelusage.CallFacts{
		RequestID: RequestIDFromContext(ctx), Surface: kind, Listener: "gateway",
		APIFamily: modelusage.FamilyChat, CallRole: modelusage.RoleJudge,
		RequestedProvider: j.providerName, RequestedModel: j.model,
		SelectedProvider: j.providerName, SelectedModel: j.model,
		Route: modelusage.RouteFacts{Decision: modelusage.DecisionNone},
	})
}

// finishJudgeUsage closes the record with the usage the provider reported.
func finishJudgeUsage(call modelusage.Call, resp *ChatResponse, err error) {
	status := http.StatusOK
	if err != nil {
		status = 0
	}
	call.UpstreamHeader(status, nil)
	if resp != nil && resp.Usage != nil {
		u := resp.Usage
		call.Usage(modelusage.ParsedUsage{
			Input: u.PromptTokens, Output: u.CompletionTokens,
			Has:           modelusage.HasInput | modelusage.HasOutput,
			ResponseModel: resp.Model,
		})
	}
	call.End(err)
}

// beginGatewayCallUsage starts the usage record of a call the gateway makes
// itself that has no token counts (decision model, Cisco AI Defense). The
// record carries role, latency and outcome; AI Defense also gets its flat
// per-call price from observability.pricing.ai_defense.
func beginGatewayCallUsage(ctx context.Context, role modelusage.CallRole, surface, model string) modelusage.Call {
	return processUsageRecorder().Begin(ctx, modelusage.CallFacts{
		RequestID: RequestIDFromContext(ctx), Surface: surface, Listener: "gateway",
		APIFamily: modelusage.FamilyOther, CallRole: role,
		SelectedProvider: surface, SelectedModel: model,
		Route: modelusage.RouteFacts{Decision: modelusage.DecisionNone},
	})
}
