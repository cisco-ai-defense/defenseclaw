// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Vault capture: a secret with a well-known issuer shape (vault.FindCapturable)
// that a sandboxed agent is given in a prompt, or writes into a tool call, is
// stored in the account's vault, replaced in the hook body by its tag
// ([vault:NAME]) before anything evaluates, audits or relays the body, and
// the call is answered block. Claude Code and Codex hooks cannot edit a
// prompt (they can block it or add context), so the prompt is stopped and
// the person sends it again without the value; the agent then uses the
// secret through `sandbox run --vault NAME`, as a placeholder OpenShell swaps
// for the value only on the way to the secret's host.
//
// It runs in the process that owns the account's vault: the per-user gateway
// (OSS, before handleAgentHook evaluates) or the per-user sandbox daemon (a
// standalone managed host, before sandboxRelayForwarder relays), so the
// managed gateway only ever sees the redacted body. It runs only for
// sandbox hook calls of the connectors whose hook body it reads, and only
// when the ingress has a vault (openshell.vault.auto_capture, on by default).

// sandboxVaultCaptureConnectors are the connectors whose prompt and
// pre-tool hook bodies capture reads.
var sandboxVaultCaptureConnectors = map[string]bool{"claudecode": true, "codex": true}

const (
	vaultCaptureEventPrompt = "UserPromptSubmit"
	vaultCaptureEventTool   = "PreToolUse"
)

// sandboxVaultCapture is what one hook call's capture did.
type sandboxVaultCapture struct {
	Event string
	// Entries are the vault entries the call's secrets are kept as, in
	// order, one per distinct value.
	Entries []vault.Entry
	// Err is set when the vault could not keep a secret; the value is
	// still removed from the body and the call is still stopped.
	Err error
}

// captureSandboxVault returns body with its capturable secrets replaced by
// their vault tags, and what it captured (nil: nothing to capture, body
// unchanged).
func captureSandboxVault(ctx context.Context, store *vault.Store, connectorName string, body []byte) ([]byte, *sandboxVaultCapture) {
	if store == nil || len(body) == 0 {
		return body, nil
	}
	binding, ok := sandboxauth.FromContext(ctx)
	if !ok {
		return body, nil
	}
	name := sandboxauth.CanonicalConnector(connectorName)
	if !sandboxVaultCaptureConnectors[name] {
		return body, nil
	}
	var head struct {
		Event string `json:"hook_event_name"`
	}
	if json.Unmarshal(body, &head) != nil || (head.Event != vaultCaptureEventPrompt && head.Event != vaultCaptureEventTool) {
		return body, nil
	}
	text := string(body)
	found := vault.FindCapturable(text)
	if len(found) == 0 {
		return body, nil
	}
	out := &sandboxVaultCapture{Event: head.Event}
	// A tool call's secret was written by the agent's model: it has seen it.
	exposed := head.Event == vaultCaptureEventTool
	where := "prompt"
	if exposed {
		where = "tool call"
	}
	from := strings.TrimSpace(fmt.Sprintf("%s %s in sandbox %s", name, where, binding.SandboxName))
	names := map[string]string{}
	for _, f := range found {
		value := text[f.Start:f.End]
		if _, done := names[value]; done {
			continue
		}
		c, err := store.Capture(vault.CaptureInput{Value: value, Kind: f.Kind, Exposed: exposed, From: from})
		if err != nil {
			names[value] = ""
			if out.Err == nil {
				out.Err = err
			}
			continue
		}
		names[value] = c.Entry.Name
		out.Entries = append(out.Entries, c.Entry)
	}
	return []byte(vault.Redact(text, found, names)), out
}

// message is what the agent (and, for a prompt, the person) is told.
func (c *sandboxVaultCapture) message() string {
	if len(c.Entries) == 0 {
		why := "it could not be saved"
		if c.Err != nil {
			why = c.Err.Error()
		}
		return "DefenseClaw stopped this call: it carried a secret, and your vault could not keep it (" + why +
			"). The secret was not sent on. Send it again without the value."
	}
	first := c.Entries[0].Name
	var kept, flags, unbound []string
	for _, e := range c.Entries {
		if t := e.Target(); t != "" {
			kept = append(kept, e.Name+" (sent only to "+t+")")
		} else {
			kept = append(kept, e.Name)
			unbound = append(unbound, "defenseclaw sandbox vault bind "+e.Name+" --host HOST")
		}
		flags = append(flags, "--vault "+e.Name)
	}
	bind := ""
	if len(unbound) > 0 {
		bind = " First give it a host: " + strings.Join(unbound, "; ") + "."
	}
	if c.Event == vaultCaptureEventPrompt {
		return fmt.Sprintf("DefenseClaw moved the secret in your prompt into your vault as %s and stopped the prompt, "+
			"so the model never saw it. Send the prompt again without the value.%s To let an agent use it, start a sandbox "+
			"with `defenseclaw sandbox run <harness> %s`: the agent reads $%s, a placeholder that OpenShell swaps for the "+
			"value only on the way to its host.", strings.Join(kept, ", "), bind, strings.Join(flags, " "), first)
	}
	return fmt.Sprintf("DefenseClaw stopped this tool call: it carried a secret, now saved in the vault as %s. "+
		"Never write secret values into commands or files: use $%s instead, which works in a sandbox started with %s.%s "+
		"The value was in the model's output, so it is marked exposed: rotate it with its issuer.",
		strings.Join(kept, ", "), first, strings.Join(flags, " "), bind)
}

// applySandboxVaultCapture turns a verdict into the capture's block.
func (a *APIServer) applySandboxVaultCapture(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	resp agentHookResponse,
	c *sandboxVaultCapture,
) agentHookResponse {
	resp.Action, resp.RawAction, resp.Mode, resp.WouldBlock = "block", "block", "action", true
	if resp.Severity != "CRITICAL" {
		resp.Severity = "HIGH"
	}
	resp.Findings = nil
	if req.HookEventName == "" {
		req.HookEventName = c.Event
	}
	return a.renderSandboxVerdict(ctx, profile, req, rawBody, payload, resp, c.message())
}

// sandboxVaultStore is the vault the ingress captures into, nil when it
// captures nothing.
func (a *APIServer) sandboxVaultStore() *vault.Store {
	a.sandboxIngressMu.RLock()
	defer a.sandboxIngressMu.RUnlock()
	if a.sandboxIngress == nil {
		return nil
	}
	return a.sandboxIngress.vault
}

// relayedVaultCaptureAnswer rewrites the managed gateway's answer to a
// relayed call whose secret the daemon captured: the call is stopped with
// the capture's message, whatever the gateway decided about the redacted
// body. The answer's other fields (delivery receipt, evaluation and agent
// ids) are kept.
func (a *APIServer) relayedVaultCaptureAnswer(ctx context.Context, connectorName string, body, answer []byte, c *sandboxVaultCapture) []byte {
	wire := map[string]interface{}{}
	if len(answer) > 0 {
		if err := json.Unmarshal(answer, &wire); err != nil || wire == nil {
			wire = map[string]interface{}{}
		}
	}
	payload := map[string]interface{}{}
	_ = json.Unmarshal(body, &payload)
	profile := a.hookProfileForRequest(ctx, connectorName)
	req := agentHookRequest{ConnectorName: connectorName, HookEventName: c.Event, Payload: payload}
	severity, _ := wire["severity"].(string)
	resp := a.applySandboxVaultCapture(ctx, profile, req, body, payload, agentHookResponse{Severity: severity}, c)
	delete(wire, "findings")
	for k, v := range renderAgentHookResponseForProfile(profile, resp) {
		wire[k] = v
	}
	out, err := json.Marshal(wire)
	if err != nil {
		out, _ = json.Marshal(renderAgentHookResponseForProfile(profile, resp))
	}
	return append(out, '\n')
}
