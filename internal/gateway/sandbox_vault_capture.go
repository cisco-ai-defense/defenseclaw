// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
// the person sends it again without the value; a sandbox then uses the
// secret through `sandbox run --vault NAME`, as a placeholder OpenShell swaps
// for the value only on the way to the secret's host. A secret the agent
// wrote into a tool call is stored exposed: no sandbox gets it until the
// person rotates and replaces it, so an agent cannot plant its own token
// under a real API's name.
//
// It runs in the process that owns the account's vault: the per-user gateway
// (OSS, before handleAgentHook evaluates) or the per-user sandbox daemon (a
// standalone managed host, before sandboxRelayForwarder relays), so the
// managed gateway only ever sees the redacted body. The daemon tells the
// managed gateway what it captured (names and hosts, never values) in
// sandboxrelay.VaultCaptureHeader, so the managed gateway answers and audits
// the call as the block it is. It runs only for sandbox hook calls of the
// connectors whose hook body it reads, and only when the ingress has a vault
// (openshell.vault.auto_capture, on by default).

// sandboxVaultCaptureConnectors are the connectors whose prompt and
// pre-tool hook bodies capture reads.
var sandboxVaultCaptureConnectors = map[string]bool{"claudecode": true, "codex": true}

const (
	vaultCaptureEventPrompt = "UserPromptSubmit"
	vaultCaptureEventTool   = "PreToolUse"
	// maxVaultCaptureHeaderEntries bounds the relay header's entries.
	maxVaultCaptureHeaderEntries = 16
)

// sandboxVaultCapture is what one hook call's capture did.
type sandboxVaultCapture struct {
	Event string
	// Sandbox names the sandbox, when known, for the message.
	Sandbox string
	// Entries are the vault entries the call's secrets are kept as, in
	// order, one per distinct value.
	Entries []vault.Entry
	// Err is set when the vault could not keep the secrets; the values are
	// still removed from the body and the call is still stopped.
	Err error
}

// captureSandboxVault returns body with its capturable secrets replaced by
// their vault tags, and what it captured (nil: nothing to capture, body
// unchanged). The body is decoded and every string value is scanned, so a
// secret after an escaped newline or a \u escape is found.
func captureSandboxVault(ctx context.Context, store *vault.Store, connectorName string, body []byte) ([]byte, *sandboxVaultCapture) {
	if store == nil || len(body) == 0 || !mayHoldCapturable(body) {
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
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]interface{}
	if dec.Decode(&doc) != nil {
		return body, nil
	}
	event, _ := doc["hook_event_name"].(string)
	if event != vaultCaptureEventPrompt && event != vaultCaptureEventTool {
		return body, nil
	}
	type hit struct{ value, kind string }
	var hits []hit
	seen := map[string]bool{}
	visitStrings(doc, func(s string) string {
		for _, f := range vault.FindCapturable(s) {
			if v := s[f.Start:f.End]; !seen[v] {
				seen[v] = true
				hits = append(hits, hit{v, f.Kind})
			}
		}
		return s
	})
	if len(hits) == 0 {
		return body, nil
	}
	exposed := event == vaultCaptureEventTool
	where := "prompt"
	if exposed {
		where = "tool call"
	}
	from := strings.TrimSpace(fmt.Sprintf("%s %s in sandbox %s", name, where, binding.SandboxName))
	ins := make([]vault.CaptureInput, 0, len(hits))
	for _, h := range hits {
		ins = append(ins, vault.CaptureInput{Value: h.value, Kind: h.kind, Exposed: exposed, From: from})
	}
	out := &sandboxVaultCapture{Event: event, Sandbox: binding.SandboxName}
	names := map[string]string{}
	if res, err := store.CaptureAll(ins, vault.CaptureWait); err != nil {
		out.Err = err
	} else {
		have := map[string]bool{}
		for i, c := range res {
			names[hits[i].value] = c.Entry.Name
			if !have[c.Entry.Name] {
				have[c.Entry.Name] = true
				out.Entries = append(out.Entries, c.Entry)
			}
		}
	}
	redacted := visitStrings(doc, func(s string) string { return vault.Redact(s, vault.FindCapturable(s), names) })
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redacted); err != nil {
		// Never forward the value: an empty event body still evaluates and
		// is answered block.
		return []byte(`{"hook_event_name":"` + event + `"}`), out
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), out
}

// mayHoldCapturable is the cheap first screen: no issuer prefix, nothing
// to capture.
func mayHoldCapturable(body []byte) bool {
	for _, p := range vault.Prefixes {
		if bytes.Contains(body, []byte(p)) {
			return true
		}
	}
	return false
}

// visitStrings returns v with every string value replaced by f(value).
func visitStrings(v interface{}, f func(string) string) interface{} {
	switch t := v.(type) {
	case string:
		return f(t)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, x := range t {
			out[k] = visitStrings(x, f)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, x := range t {
			out[i] = visitStrings(x, f)
		}
		return out
	}
	return v
}

// errorText says why the vault could not keep a capture, without a path.
func (c *sandboxVaultCapture) errorText() string {
	switch {
	case c.Err == nil:
		return "it could not be saved"
	case errors.Is(c.Err, vault.ErrBusy):
		return "the vault is busy: another DefenseClaw command is writing it"
	case errors.Is(c.Err, vault.ErrCaptureFull), errors.Is(c.Err, vault.ErrFull):
		return c.Err.Error()
	}
	return "the vault could not be written; run `defenseclaw sandbox vault list` to see why"
}

// message is what the agent (and, for a prompt, the person) is told.
func (c *sandboxVaultCapture) message() string {
	if len(c.Entries) == 0 {
		return "DefenseClaw stopped this call: it carried a secret, and your vault could not keep it (" + c.errorText() +
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
	if c.Event == vaultCaptureEventPrompt {
		bind := ""
		if len(unbound) > 0 {
			bind = " First give it a host: " + strings.Join(unbound, "; ") + "."
		}
		sandbox := c.Sandbox
		if sandbox == "" {
			sandbox = "<name>"
		}
		return fmt.Sprintf("DefenseClaw moved the secret in your prompt into your vault as %s and stopped the prompt "+
			"before it reached the model. Delete the value from your input and send the prompt again without it.%s To let an "+
			"agent use it, start a sandbox with `defenseclaw sandbox run <harness> %s`: the agent reads $%s, a placeholder "+
			"that OpenShell swaps for the value only on the way to its host. The agent's session log in this sandbox still "+
			"holds the stopped prompt: delete the sandbox when you are done (`defenseclaw sandbox delete %s`).",
			strings.Join(kept, ", "), bind, strings.Join(flags, " "), first, sandbox)
	}
	var names []string
	for _, e := range c.Entries {
		names = append(names, e.Name)
	}
	return fmt.Sprintf("DefenseClaw stopped this tool call: it carried a secret. The value is now held in the user's vault "+
		"as %s and marked exposed, because the model wrote it: the user must rotate it with its issuer and replace it "+
		"(defenseclaw sandbox vault replace %s) before any sandbox can use it. Never write secret values into commands "+
		"or files; ask the user to give the sandbox the credential through the vault.", strings.Join(names, ", "), first)
}

// header encodes the capture for the managed gateway: the event and each
// entry's name and target, never a value ("-" when nothing was kept).
func (c *sandboxVaultCapture) header() string {
	parts := []string{c.Event}
	for i, e := range c.Entries {
		if i == maxVaultCaptureHeaderEntries {
			break
		}
		parts = append(parts, e.Name+"="+e.Target())
	}
	if len(c.Entries) == 0 {
		parts = append(parts, "-")
	}
	return strings.Join(parts, " ")
}

// vaultCaptureFromHeader reads a relay header the daemon set; anything
// that does not parse strictly is ignored (nil).
func vaultCaptureFromHeader(v string) *sandboxVaultCapture {
	fields := strings.Fields(v)
	if len(fields) < 2 || len(fields) > maxVaultCaptureHeaderEntries+1 {
		return nil
	}
	c := &sandboxVaultCapture{Event: fields[0]}
	if c.Event != vaultCaptureEventPrompt && c.Event != vaultCaptureEventTool {
		return nil
	}
	if len(fields) == 2 && fields[1] == "-" {
		c.Err = errors.New("the sandbox daemon could not keep it")
		return c
	}
	for _, f := range fields[1:] {
		name, target, ok := strings.Cut(f, "=")
		if !ok || vault.ValidName(name) != nil {
			return nil
		}
		e := vault.Entry{Name: name, Exposed: c.Event == vaultCaptureEventTool}
		if target != "" {
			host, port, err := vault.ParseHost(target)
			if err != nil {
				return nil
			}
			e.Host, e.Port = host, port
		}
		c.Entries = append(c.Entries, e)
	}
	return c
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
// the capture's message whatever the gateway answered (a managed gateway
// that reads VaultCaptureHeader answers block already; an older one does
// not). The answer's other fields (delivery receipt, evaluation and agent
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
