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
	// The plugin posts run the kit's skill folder pass as the command hooks
	// do (GAP-1143): a refused folder in any skill root is taken out of the
	// agent's reach after a tool call, at session start and at idle, and a
	// call the plugin can deny is refused while a refused folder still loads
	// or a held one has no verdict. A refusal is the gateway's block shape,
	// which the plugin turns into its own deny.
	if stderr == nil {
		stderr = io.Discard
	}
	o := HookOptions{Config: cfg, Stderr: stderr}
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
	if msg := stuckSkillRefusal(o.home(), event); msg != "" {
		return writeHookPostRefusal(stdout, msg)
	}
	env := HookEnvelope{V: EnvelopeVersion, Connector: connectorName, Event: event,
		HookContract: cfg.HookContracts[connectorName], Mode: mode, KitVersion: cfg.KitVersion,
		Payload: json.RawMessage(payload), Facts: CollectFacts(connectorName, event, payload, cfg.attachCap())}
	pass := o.beginSkillPass(&env, payload)
	body, err := json.Marshal(env)
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
	if msg := o.finishSkillPass(pass, resp, err); msg != "" {
		return writeHookPostRefusal(stdout, msg)
	}
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

// writeHookPostRefusal answers the plugin with the kit's own refusal in the
// gateway's block shape (action block and a deny hook_output): the OpenCode
// and Amp plugins deny a call they can block with this reason, and the
// observe-only events ignore it.
func writeHookPostRefusal(stdout io.Writer, reason string) int {
	body, err := json.Marshal(map[string]any{"action": "block", "reason": reason,
		"hook_output": map[string]string{"decision": "deny", "reason": reason}})
	if err != nil {
		return 1
	}
	return writeJSON(stdout, map[string]any{"status": 200, "body": string(body)})
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
