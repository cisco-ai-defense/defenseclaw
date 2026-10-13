// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// HookRefusalHeader marks a hook call that only reports a refusal the hook
// made itself. The gateway records the decision and evaluates nothing.
const HookRefusalHeader = "X-DefenseClaw-Hook-Refusal"

// HookRefusalPayloadTooLarge is the HookRefusalHeader value of a call the
// hook refused because its payload is over the hook's cap.
const HookRefusalPayloadTooLarge = "payload_too_large"

// oversizedRefusalReportTimeout bounds the report, so a slow gateway never
// delays the refusal the agent is waiting for.
var oversizedRefusalReportTimeout = 2 * time.Second

// oversizedRefusalFields are the payload fields a refusal report carries: the
// event and what names the session, turn and agent. Never any content.
var oversizedRefusalFields = map[string]bool{
	"hook_event_name": true, "event": true,
	"session_id": true, "sessionId": true, "conversation_id": true, "conversationId": true,
	"turn_id": true, "generation_id": true, "agent_id": true, "agent_type": true,
	"cwd": true, "permission_mode": true, "model": true, "cursor_version": true,
	"tool_name": true, "toolName": true, "tool_use_id": true,
}

// oversizedRefusalFieldMax bounds each reported field.
const oversizedRefusalFieldMax = 512

// payloadPrefixFields reads the oversizedRefusalFields string values of a
// payload's top-level object from its first bytes. Agents put the event and
// session fields before the prompt or tool input, so the prefix the hook read
// before it stopped at its cap holds them; the scan ends at the first value
// the prefix cuts off.
func payloadPrefixFields(prefix []byte) map[string]string {
	fields := map[string]string{}
	decoder := json.NewDecoder(bytes.NewReader(prefix))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return fields
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		key, _ := token.(string)
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			break
		}
		var value string
		if oversizedRefusalFields[key] && json.Unmarshal(raw, &value) == nil &&
			value != "" && len(value) <= oversizedRefusalFieldMax {
			fields[key] = value
		}
	}
	return fields
}

// reportOversizedRefusal tells the standalone gateway that this hook refused
// a call as too large to inspect, so the refusal has an audit record with the
// connector, the user and the agent and session identities like every other
// block; before, only the local hook-failures.jsonl knew (GAP-0965,
// GAP-1042). The report carries fields, never the content. It is best
// effort: the refusal stands whatever the gateway answers.
func reportOversizedRefusal(opts Options, sp spec, fields map[string]string) {
	client, token, ok := refusalReportTransport(opts)
	if !ok {
		return
	}
	body := make(map[string]string, len(fields)+1)
	for key, value := range fields {
		body[key] = value
	}
	switch sp.connector {
	case "copilot", "antigravity":
		// Their bodies carry no event; sendHookRequest sends the bound one.
		delete(body, "hook_event_name")
		delete(body, "event")
	default:
		if event := strings.TrimSpace(opts.Event); event != "" {
			body["hook_event_name"] = event
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return
	}
	opts.HTTPClient = client
	opts.AssetFacts = nil
	opts.refusal = HookRefusalPayloadTooLarge
	if opts.ManagedStandalone && strings.TrimSpace(opts.APIAddr) == "" {
		opts.APIAddr = "127.0.0.1:1" // the Unix transport dials the socket
	}
	ctx, cancel := context.WithTimeout(context.Background(), oversizedRefusalReportTimeout)
	defer cancel()
	resp, err := sendHookRequest(ctx, opts, sp, data, token)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// refusalReportTransport is the managed standalone transport a refusal report
// uses: the peer-authorized Unix socket, or the Windows standalone gateway
// with the runtime's authenticated token. Secure Client, per-user hooks and
// a runtime that already failed send nothing.
func refusalReportTransport(opts Options) (*http.Client, string, bool) {
	if !opts.ManagedEnterprise || opts.SecureClient || strings.TrimSpace(opts.ManagedRuntimeFailure) != "" {
		return nil, "", false
	}
	client := opts.HTTPClient
	var err error
	switch {
	case opts.ManagedStandalone:
		if strings.TrimSpace(opts.ManagedUnixSocket) == "" {
			return nil, "", false
		}
		if client == nil {
			client, err = managedStandaloneHTTPClient(oversizedRefusalReportTimeout, opts.ManagedUnixSocket, opts.ManagedServiceUID)
		}
		return client, "", err == nil
	case opts.ExplainUnenrolledAccount && opts.AuthenticatedManagedToken != nil &&
		strings.TrimSpace(*opts.AuthenticatedManagedToken) != "":
		if client == nil {
			client, err = managedEnterpriseHTTPClient(oversizedRefusalReportTimeout, opts.APIAddr, opts.ManagedGatewayServiceName)
		}
		return client, strings.TrimSpace(*opts.AuthenticatedManagedToken), err == nil
	}
	return nil, "", false
}
