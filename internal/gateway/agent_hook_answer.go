// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hookAnswerBody encodes the finalized verdict before any response bytes are
// sent. A bad connector output is replaced with the same action's native
// control, so the hook can apply the verdict recorded by the audit row.
func hookAnswerBody(profile connector.HookProfile, connectorName string, req agentHookRequest, resp agentHookResponse, receiptID string) []byte {
	body, err := encodeHookAnswer(profile, resp, receiptID, nil)
	if err == nil {
		return body
	}
	fmt.Fprintf(os.Stderr, "[gateway] hook answer encoding failed connector=%s event=%s action=%s: %v\n",
		connectorName, req.HookEventName, resp.Action, err)
	if req.ConnectorName == "" {
		req.ConnectorName = connectorName
	}
	fallback := resp
	fallback.HookOutput = callbackFreeHookOutput(profile, req, resp)
	if body, err = encodeHookAnswer(profile, fallback, receiptID, nil); err == nil {
		return body
	}
	// The outer answer fields are fixed types. This final form is readable
	// even if a future callback-free output has an encoding defect.
	fallback.HookOutput = nil
	body, _ = encodeHookAnswer(profile, fallback, receiptID, nil)
	return body
}

func callbackFreeHookOutput(profile connector.HookProfile, req agentHookRequest, resp agentHookResponse) (output map[string]interface{}) {
	defer func() {
		if recover() != nil {
			output = nil
		}
	}()
	switch {
	case req.ConnectorName == "claudecode":
		return claudeCodeOutput(claudeCodeHookRequest{HookEventName: req.HookEventName},
			resp.Action, resp.RawAction, resp.Reason, resp.AdditionalContext)
	case req.ConnectorName == "codex":
		return codexOutput(req.HookEventName, resp.Action, resp.RawAction, resp.Reason, resp.AdditionalContext)
	case req.ConnectorName == "copilot" && profile.ContractID == connector.CopilotVSCodeLocalContractID:
		return connector.CopilotVSCodeLocalHookOutput(req.HookEventName, resp.Action,
			connectorReason(req.ConnectorName, resp.Action, req.ToolName, resp.Reason), resp.AdditionalContext)
	default:
		return hookOutputFor(req, resp.Action, resp.RawAction, resp.Reason, resp.AdditionalContext, profile.Capabilities)
	}
}

// encodeHookAnswer matches json.Encoder's HTML escaping and final newline.
// A marshaler panic is reported to the caller and never reaches the writer.
func encodeHookAnswer(profile connector.HookProfile, resp agentHookResponse, receiptID string, onPanic func(any)) (body []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if onPanic != nil {
				onPanic(recovered)
			}
			body, err = nil, fmt.Errorf("render panic: %v", recovered)
		}
	}()
	wire := renderAgentHookResponseForProfile(profile, resp)
	if receiptID != "" {
		wire["delivery_receipt"] = receiptID
	}
	if body, err = json.Marshal(wire); err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func writeHookAnswer(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
