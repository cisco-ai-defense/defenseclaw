// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hookAnswerBody encodes the finalized verdict before any response byte is
// sent (GAP-1097). A connector output that cannot be encoded is replaced by
// the same action's callback-free native control, so the hook applies the
// verdict the audit row records.
func (a *APIServer) hookAnswerBody(ctx context.Context, profile connector.HookProfile, connectorName string, req agentHookRequest, resp agentHookResponse, receiptID string) []byte {
	onPanic := func(any) {}
	body, err := encodeHookAnswer(profile, resp, receiptID, onPanic)
	if err == nil {
		return body
	}
	fmt.Fprintf(os.Stderr, "[gateway] hook answer encoding failed connector=%s event=%s action=%s: %v\n",
		connectorName, req.HookEventName, resp.Action, err)
	if req.ConnectorName == "" {
		req.ConnectorName = connectorName
	}
	fallback := resp
	fallback.HookOutput = callbackFreeHookOutput(profile, req, resp, onPanic)
	if body, err = encodeHookAnswer(profile, fallback, receiptID, onPanic); err == nil {
		return body
	}
	// The outer answer fields have fixed types, so this last form encodes
	// even if a callback-free output has a defect.
	fallback.HookOutput = nil
	body, _ = encodeHookAnswer(profile, fallback, receiptID, onPanic)
	return body
}

// callbackFreeHookOutput is the native output of resp's action for the
// connector, built from fixed strings only.
func callbackFreeHookOutput(profile connector.HookProfile, req agentHookRequest, resp agentHookResponse, onPanic func(any)) (output map[string]interface{}) {
	defer func() {
		if recovered := recover(); recovered != nil {
			onPanic(recovered)
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

// encodeHookAnswer renders and encodes one answer as json.Encoder does (HTML
// escaping, final newline). A marshaler panic is reported and never reaches
// the writer.
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
