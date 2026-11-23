// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Vault capture: a secret with a well-known issuer shape (vault.FindCapturable)
// in any hook body of a sandboxed harness (a prompt, a tool call, a tool's
// output, the agent's reply) is stored in the account's vault and replaced
// in the body by its tag ([vault:NAME]) before anything evaluates, audits or
// relays the body. connector.SandboxVaultCaptureEventFor places the event:
// a prompt the hook stops keeps the secret unconfirmed; everywhere else the
// model has seen (or wrote) it, so it is stored exposed. The call gets the
// strongest answer the event has (block, or alert where the event cannot
// stop anything or a block would restart the agent's turn). Claude Code and Codex hooks cannot edit a
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
// the call as the capture it is. It runs only for sandbox hook calls of the
// harnesses that run in a sandbox, and only when the ingress has a vault
// (openshell.vault.auto_capture, on by default).

const (
	vaultCaptureEventPrompt = "UserPromptSubmit"
	vaultCaptureEventTool   = "PreToolUse"
	// maxVaultCaptureHeaderEntries bounds the relay header's entries.
	maxVaultCaptureHeaderEntries = 16
)

// sandboxVaultCapture is what one hook call's capture did.
type sandboxVaultCapture struct {
	// Connector and Event place the call (connector.SandboxVaultCaptureEventFor).
	Connector string
	Event     string
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
func captureSandboxVault(ctx context.Context, store *vault.Store, connectorName string, header http.Header, body []byte) ([]byte, *sandboxVaultCapture) {
	if store == nil || len(body) == 0 || !mayHoldCapturable(body) {
		return body, nil
	}
	binding, ok := sandboxauth.FromContext(ctx)
	if !ok {
		return body, nil
	}
	name := sandboxauth.CanonicalConnector(connectorName)
	if _, reads := connector.SandboxVaultCaptureEventFor(name, ""); !reads {
		return body, nil
	}
	if !hookToolCallJSONUnambiguous(name, body) {
		// Duplicate keys or trailing values: the existing ambiguous-JSON
		// rejection answers it; capture never picks one reading.
		return body, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]interface{}
	if dec.Decode(&doc) != nil {
		return body, nil
	}
	event := sandboxVaultCaptureEventName(name, header, doc)
	point, _ := connector.SandboxVaultCaptureEventFor(name, event)
	type hit struct{ value, kind string }
	var hits []hit
	seen := map[string]bool{}
	_, _ = visitStrings(doc, func(s string) string {
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
	from := strings.TrimSpace(fmt.Sprintf("%s %s (%s) in sandbox %s", name, point.Where(), event, binding.SandboxName))
	ins := make([]vault.CaptureInput, 0, len(hits))
	for _, h := range hits {
		ins = append(ins, vault.CaptureInput{Value: h.value, Kind: h.kind, Exposed: point.Exposed(), From: from})
	}
	out := &sandboxVaultCapture{Connector: name, Event: event, Sandbox: binding.SandboxName}
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
	redacted, collided := visitStrings(doc, func(s string) string { return vault.Redact(s, vault.FindCapturable(s), names) })
	if collided {
		// Two keys redacted to the same tag: never forward the value, and
		// never drop one of them silently. The call is answered block.
		return []byte(`{"hook_event_name":"` + event + `"}`), out
	}
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

// sandboxVaultCaptureEventName is the hook event a sandbox call names, as
// handleAgentHook reads it: Copilot and Antigravity name it in the hook
// command's header, the others in the body. A name that is not a plain
// token is "hook" (placed VaultCaptureOther: stored exposed, alerted).
func sandboxVaultCaptureEventName(name string, header http.Header, doc map[string]interface{}) string {
	event := ""
	switch name {
	case "copilot":
		if e := strings.TrimSpace(header.Get("X-DefenseClaw-Copilot-Event")); e != "" {
			event, _ = copilotargs.LocalDialect(copilotHookDialectFromHeaders(header), e)
		}
	case "antigravity":
		event = strings.TrimSpace(header.Get("X-DefenseClaw-Antigravity-Event"))
	}
	if event == "" {
		event = firstString(doc, "hook_event_name", "hookEventName", "event_type", "eventType",
			"event_name", "eventName", "agent_action_name", "event")
	}
	if !validVaultCaptureEventName(event) {
		return "hook"
	}
	return event
}

// validVaultCaptureEventName: 1 to 64 letters, digits, '.', '_' or '-'.
func validVaultCaptureEventName(event string) bool {
	if event == "" || len(event) > 64 {
		return false
	}
	for _, r := range event {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// point places the call; a connector capture does not read is
// VaultCaptureOther.
func (c *sandboxVaultCapture) point() connector.VaultCaptureEvent {
	p, _ := connector.SandboxVaultCaptureEventFor(c.Connector, c.Event)
	return p
}

// mayHoldCapturable is the cheap first screen: no issuer prefix, nothing
// to capture.
func mayHoldCapturable(body []byte) bool {
	if bytes.Contains(body, []byte(`\u`)) {
		// A \u escape can spell a prefix; the decoded strings decide.
		return true
	}
	for _, p := range vault.Prefixes {
		if bytes.Contains(body, []byte(p)) {
			return true
		}
	}
	return false
}

// visitStrings returns v with every string, object keys included,
// replaced by f(value); collided reports two keys of one object that f
// mapped to the same key.
func visitStrings(v interface{}, f func(string) string) (interface{}, bool) {
	switch t := v.(type) {
	case string:
		return f(t), false
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		collided := false
		for k, x := range t {
			nk := f(k)
			if _, taken := out[nk]; taken {
				collided = true
			}
			nv, c := visitStrings(x, f)
			out[nk] = nv
			collided = collided || c
		}
		return out, collided
	case []interface{}:
		out := make([]interface{}, len(t))
		collided := false
		for i, x := range t {
			nv, c := visitStrings(x, f)
			out[i] = nv
			collided = collided || c
		}
		return out, collided
	}
	return v, false
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
	point := c.point()
	if len(c.Entries) == 0 {
		if point.Point != connector.VaultCapturePrompt && point.Point != connector.VaultCaptureToolCall {
			return "DefenseClaw found a secret in this " + point.Where() + ", and your vault could not keep it (" + c.errorText() +
				"). The model may have seen it: rotate it with its issuer. Do not use or repeat the value."
		}
		return "DefenseClaw stopped this call: it carried a secret, and your vault could not keep it (" + c.errorText() +
			"). The secret was not sent on. Send it again without the value."
	}
	first := c.Entries[0].Name
	prompt := point.Point == connector.VaultCapturePrompt
	if !prompt && point.Point != connector.VaultCaptureToolCall {
		return c.exposedMessage(point)
	}
	var kept, flags, unbound, exposed []string
	for _, e := range c.Entries {
		if e.Exposed && prompt {
			exposed = append(exposed, e.Name)
			continue
		}
		if t := e.Target(); t != "" {
			kept = append(kept, e.Name+" (sent only to "+t+")")
		} else {
			kept = append(kept, e.Name)
			unbound = append(unbound, "defenseclaw sandbox vault bind "+e.Name+" --host HOST")
		}
		flags = append(flags, "--vault "+e.Name)
	}
	if prompt && len(flags) == 0 {
		return fmt.Sprintf("DefenseClaw stopped the prompt before it reached the model: it carried a secret your vault "+
			"already holds as %s, marked exposed (an agent's model may have seen it). Rotate it with its issuer and run "+
			"`defenseclaw sandbox vault replace %s` before a sandbox can use it.", strings.Join(exposed, ", "), exposed[0])
	}
	if prompt {
		bind := ""
		if len(unbound) > 0 {
			bind = " First give it a host: " + strings.Join(unbound, "; ") + "."
		}
		if len(exposed) > 0 {
			bind += " " + strings.Join(exposed, ", ") + " is marked exposed: rotate and replace it first."
		}
		first = strings.TrimPrefix(flags[0], "--vault ")
		sandbox := c.Sandbox
		if sandbox == "" {
			sandbox = "<name>"
		}
		return fmt.Sprintf("DefenseClaw moved the secret in your prompt into your vault as %s and stopped the prompt "+
			"before it reached the model. Delete the value from your input and send the prompt again without it.%s To let an "+
			"agent use it, check it is yours (`defenseclaw sandbox vault confirm %s`), then start a sandbox with "+
			"`defenseclaw sandbox run <harness> %s`: the agent reads $%s, a placeholder "+
			"that OpenShell swaps for the value only on the way to its host. The agent's session log in this sandbox still "+
			"holds the stopped prompt: delete the sandbox when you are done (`defenseclaw sandbox delete %s`).",
			strings.Join(kept, ", "), bind, first, strings.Join(flags, " "), first, sandbox)
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

// exposedMessage is the answer where the model has seen the secret: a
// prompt the hook could not stop, a tool's output, the agent's reply.
func (c *sandboxVaultCapture) exposedMessage(point connector.VaultCaptureEvent) string {
	var names []string
	for _, e := range c.Entries {
		names = append(names, e.Name)
	}
	held, first := strings.Join(names, ", "), names[0]
	if point.Point == connector.VaultCapturePromptSeen {
		return fmt.Sprintf("DefenseClaw found a secret in this prompt and moved it into the user's vault as %s, marked exposed: "+
			"this agent's hooks cannot keep a prompt from the model, so the model may have seen it. Do not carry out the prompt "+
			"with this value and never repeat or write it. The user must rotate it with its issuer and replace it "+
			"(`defenseclaw sandbox vault replace %s`) before any sandbox can use it, and send the prompt again without the value.", held, first)
	}
	return fmt.Sprintf("DefenseClaw found a secret in this %s and moved it into the user's vault as %s, marked exposed, because "+
		"the model has seen it. Do not use, repeat or write the value. The user must rotate it with its issuer and replace it "+
		"(`defenseclaw sandbox vault replace %s`) before any sandbox can use it; ask the user to give the sandbox the credential "+
		"through the vault.", point.Where(), held, first)
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

// vaultCaptureFromHeader reads a relay header the daemon set for a call of
// connectorName; anything that does not parse strictly is ignored (nil).
func vaultCaptureFromHeader(connectorName, v string) *sandboxVaultCapture {
	fields := strings.Fields(v)
	if len(fields) < 2 || len(fields) > maxVaultCaptureHeaderEntries+1 {
		return nil
	}
	name := sandboxauth.CanonicalConnector(connectorName)
	if _, reads := connector.SandboxVaultCaptureEventFor(name, ""); !reads || !validVaultCaptureEventName(fields[0]) {
		return nil
	}
	c := &sandboxVaultCapture{Connector: name, Event: fields[0]}
	if len(fields) == 2 && fields[1] == "-" {
		c.Err = errors.New("the sandbox daemon could not keep it")
		return c
	}
	for _, f := range fields[1:] {
		name, target, ok := strings.Cut(f, "=")
		if !ok || vault.ValidName(name) != nil {
			return nil
		}
		e := vault.Entry{Name: name, Exposed: c.point().Exposed()}
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

// stops reports whether the call is answered block.
func (c *sandboxVaultCapture) stops() bool { return c.point().Stop }

// applySandboxVaultCapture turns a verdict into the capture's answer: block
// where the event can stop (or the verdict blocked already), otherwise an
// alert that still carries the capture's message.
func (a *APIServer) applySandboxVaultCapture(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	resp agentHookResponse,
	c *sandboxVaultCapture,
) agentHookResponse {
	if c.stops() || resp.Action == "block" {
		resp.Action, resp.RawAction, resp.Mode, resp.WouldBlock = "block", "block", "action", true
	} else {
		resp.Action, resp.RawAction, resp.Mode, resp.WouldBlock = "alert", "alert", "action", false
	}
	if resp.Severity != "CRITICAL" {
		resp.Severity = "HIGH"
	}
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
// the capture's message whatever the gateway answered (alerted where the
// event cannot stop) (a managed gateway
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
