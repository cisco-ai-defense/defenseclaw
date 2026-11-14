// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// RunHookPost is `defenseclaw-actor-hook hook-post`, the native-post
// contract of the in-agent plugins (opencode-plugin, amp-plugin): stdin
// {"path", "headers", "body"} for one gateway post, stdout {"status",
// "body"} with the gateway's answer, and a non-zero exit when there is no
// answer, which the plugin handles as its own failure. The plugin keeps
// its verdict logic; the kit gives it the actor transport (envelope with
// facts, placeholder header, kept-alive helper) instead of a bearer post,
// so a plugin connector needs no HTTP of its own in an actor. Its other
// arguments (--api-addr, --max-time, ...) are the host transport's and are
// ignored.
func RunHookPost(ctx context.Context, cfg Config, stdin io.Reader, stdout, stderr io.Writer,
	send func(ctx context.Context, r Request) (Response, string, error)) int {
	var in struct {
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxPayloadBytes+64<<10))
	if err != nil || json.Unmarshal(raw, &in) != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-hook: hook-post needs {path, headers, body} on stdin")
		return 2
	}
	connectorName, ok := pluginConnector(in.Path)
	if !ok {
		fmt.Fprintf(stderr, "defenseclaw-actor-hook: hook-post does not serve %q\n", in.Path)
		return 2
	}
	payload := []byte(in.Body)
	if int64(len(payload)) > maxPayloadBytes || !json.Valid(payload) {
		fmt.Fprintln(stderr, "defenseclaw-actor-hook: hook-post body is not a JSON event of at most 1 MiB")
		return 2
	}
	mode := Mode(func(string) string { return "" })
	var view struct {
		Event string `json:"hook_event_name"`
		Alt   string `json:"event"`
	}
	_ = json.Unmarshal(payload, &view)
	event := view.Event
	if event == "" {
		event = view.Alt
	}
	body, err := json.Marshal(HookEnvelope{V: EnvelopeVersion, Connector: connectorName, Event: event,
		HookContract: cfg.HookContracts[connectorName], Mode: mode, KitVersion: cfg.KitVersion,
		Payload: json.RawMessage(payload), Facts: CollectFacts(connectorName, event, payload, cfg.attachCap())})
	if err != nil {
		return 2
	}
	header := map[string]string{"X-DefenseClaw-Actor-Mode": mode}
	for k, v := range in.Headers {
		// The plugin's own DefenseClaw headers pass; its bearer and the
		// transport's headers do not (reserved).
		if strings.HasPrefix(strings.ToLower(k), "x-defenseclaw-") {
			header[k] = v
		}
	}
	if send == nil {
		send = defaultSend(cfg)
	}
	resp, _, err := send(ctx, Request{Path: HookPathPrefix + connectorName, Header: header, Body: body})
	if err != nil {
		if errors.Is(err, ErrUnreachable) {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook: the DefenseClaw gateway in the cluster did not answer")
		} else {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook:", err)
		}
		return 1
	}
	return writeJSON(stdout, map[string]any{"status": resp.Status, "body": string(resp.Body)})
}

func writeJSON(w io.Writer, v any) int {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return 1
	}
	return 0
}

// pluginConnector maps a plugin's host hook path to its connector.
func pluginConnector(p string) (string, bool) {
	switch p {
	case "/api/v1/opencode/hook":
		return "opencode", true
	case "/api/v1/amp/hook":
		return "amp", true
	}
	return "", false
}
