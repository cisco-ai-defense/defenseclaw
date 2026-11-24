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
	"os"
	"strings"
	"time"

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
// model has seen (or wrote) it, so it is stored exposed. A prompt, a tool
// call or a tool's output stores a value the vault does not hold yet (a key
// an agent assembled as its tool ran is first seen in the output); a reply
// or another event only marks a held value exposed. Values from the model's
// side have their own bound in the vault, so they never use up the room
// prompts need. In action mode the call gets the strongest answer the
// event has (block, or alert where the event cannot stop anything or a
// block would restart the agent's turn); the configured mode is never
// overridden, so in observe mode the capture is still stored and reported
// and nothing is stopped (a prompt that goes on is then stored exposed).
// Claude Code and Codex hooks cannot edit a
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
	// maxVaultCaptureHeaderEntries bounds the relay header's entries.
	maxVaultCaptureHeaderEntries = 16
	// vaultCaptureRetryWait bounds each background retry's wait for the
	// vault lock when a hook call could not write an exposure.
	vaultCaptureRetryWait = 5 * time.Second
	// sandboxVaultExposureRuleID is the alert of an exposure the vault has
	// not written yet when its retries give up.
	sandboxVaultExposureRuleID = "sandbox_vault_exposure"
	// vaultCaptureUnkeptField ends a relay header whose call had a value
	// removed that the vault does not hold.
	vaultCaptureUnkeptField = "+unkept"
)

// vaultExposureRetrySlots bounds the exposure retries that run at once;
// past it the pending record alone keeps the value from any sandbox.
var vaultExposureRetrySlots = make(chan struct{}, 8)

// vaultExposureRetryDelays are the waits before each exposure retry.
var vaultExposureRetryDelays = []time.Duration{250 * time.Millisecond, time.Second, 4 * time.Second, 15 * time.Second}

// errVaultCaptureAmbiguous: the body has duplicate keys or trailing data,
// so capture cannot read one meaning of it; nothing of it is forwarded.
var errVaultCaptureAmbiguous = errors.New("the call's JSON is ambiguous (a repeated key or extra data)")

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
	// Err is set when the vault could not keep a secret; the values are
	// still removed from the body and the call is still answered.
	Err error
	// Unkept: a value was removed from the body and is not in Entries (the
	// vault could not keep it, or the event stores nothing new).
	Unkept bool
	// NotStopped: a prompt the event could have stopped went on (observe
	// mode), so its secrets were marked exposed.
	NotStopped bool
	// markExposed marks this call's values exposed in the vault, waiting at
	// most wait for its lock; applyPending writes the vault's pending
	// exposures (the retries only). Set only where the vault is owned
	// (never from a relay header); markExposed holds the values, so it is
	// never logged.
	markExposed  func(wait time.Duration) error
	applyPending func(wait time.Duration) error
	// retrying: followVaultExposure started this capture's retries.
	retrying bool
	// exposeErr: the capture exposed values and could not write the vault
	// (vault.ErrExposurePending or vault.ErrExposureNotRecorded).
	exposeErr error
}

// captureSandboxVault returns body with its capturable secrets replaced by
// their vault tags, and what it captured (nil: nothing to capture, body
// unchanged). The body is decoded and every string value is scanned, so a
// secret after an escaped newline or a \u escape is found. promptGoesOn,
// when set, says the call's answer will not stop it (observe mode): a
// prompt is then stored exposed in the capture's one write.
func captureSandboxVault(ctx context.Context, store *vault.Store, connectorName string, header http.Header, body []byte, promptGoesOn func() bool) ([]byte, *sandboxVaultCapture) {
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
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]interface{}
	decodeErr := dec.Decode(&doc)
	if !hookToolCallJSONUnambiguous(name, body) {
		// Duplicate keys or trailing values may carry a secret: capture
		// never picks one reading, and nothing of the body goes on, on any
		// route (a prompt or output event relayed to a managed gateway
		// included). The body left is still ambiguous (its event key twice),
		// so the gateway's ambiguous-JSON handling answers it exactly as
		// before: a structured tool call is denied as unread, any other
		// event gets the audited rejection its hook's fail mode decides.
		event := sandboxVaultCaptureEventName(name, header, doc)
		return []byte(`{"hook_event_name":"` + event + `","hook_event_name":"` + event + `"}`), &sandboxVaultCapture{
			Connector: name, Event: event, Sandbox: binding.SandboxName, Err: errVaultCaptureAmbiguous, Unkept: true,
		}
	}
	if decodeErr != nil {
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
	exposed, notStopped := point.Exposed(), false
	if point.Point == connector.VaultCapturePrompt && promptGoesOn != nil && promptGoesOn() {
		// The answer will not stop the prompt: it reaches the model, so it
		// is stored exposed now, in one write.
		exposed, notStopped = true, true
	}
	ins := make([]vault.CaptureInput, 0, len(hits))
	for _, h := range hits {
		ins = append(ins, vault.CaptureInput{
			Value: h.value, Kind: h.kind, Exposed: exposed, From: from,
			FromModel: point.FromModel(), KnownOnly: !point.Stores(), Sandbox: binding.SandboxName,
		})
	}
	out := &sandboxVaultCapture{Connector: name, Event: event, Sandbox: binding.SandboxName, NotStopped: notStopped}
	out.markExposed = func(wait time.Duration) error {
		again := make([]vault.CaptureInput, len(ins))
		for i, in := range ins {
			in.Exposed, in.KnownOnly = true, true
			again[i] = in
		}
		_, err := store.CaptureAll(again, wait)
		return err
	}
	out.applyPending = store.ApplyPendingExposures
	names := map[string]string{}
	// A store error still returns the values the vault holds (their
	// exposure is written whatever else failed). When nothing could be
	// written, the exposed values are recorded as pending exposures, which
	// keep them from any sandbox; the caller retries the write
	// (followVaultExposure).
	res, err := store.CaptureAll(ins, vault.CaptureWait)
	out.Err = err
	if errors.Is(err, vault.ErrExposurePending) || errors.Is(err, vault.ErrExposureNotRecorded) {
		out.exposeErr = err
	}
	have := map[string]bool{}
	for i, c := range res {
		if c.Entry.Name == "" {
			out.Unkept = true
			continue
		}
		e := c.Entry
		e.Exposed = e.Exposed || exposed
		names[hits[i].value] = e.Name
		if !have[e.Name] {
			have[e.Name] = true
			out.Entries = append(out.Entries, e)
		}
	}
	if len(res) < len(hits) {
		out.Unkept = true
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

// validVaultCaptureEventName: 1 to 64 letters, digits, '.', '_' or '-',
// and not shaped like a credential (the name is carried unredacted into
// the body, the entry's CapturedFrom, the relay header and the messages).
func validVaultCaptureEventName(event string) bool {
	if event == "" || len(event) > 64 {
		return false
	}
	for _, r := range event {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	if len(vault.FindCapturable(event)) > 0 {
		return false
	}
	_, masked := vault.MaskCapturable([]byte(event))
	return !masked
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
	case errors.Is(c.Err, vault.ErrCaptureFull), errors.Is(c.Err, vault.ErrModelCaptureFull), errors.Is(c.Err, vault.ErrFull):
		return c.Err.Error()
	case errors.Is(c.Err, errVaultCaptureAmbiguous):
		return c.Err.Error() + ", so DefenseClaw passed none of it on"
	case errors.Is(c.Err, vault.ErrSealRemoved):
		return "your vault was sealed and is now a plain file or gone, so DefenseClaw kept nothing in it; " +
			"run `defenseclaw sandbox vault list` to seal it again"
	case errors.Is(c.Err, vault.ErrVaultChanged):
		return "your vault looks changed: its seal is not the one DefenseClaw pinned, so DefenseClaw kept nothing in it; " +
			"run `defenseclaw sandbox vault list` to check it with your vault key"
	}
	return "the vault could not be written; run `defenseclaw sandbox vault list` to see why"
}

// message is what the agent (and, for a prompt, the person) is told.
func (c *sandboxVaultCapture) message() string {
	msg := c.keptMessage()
	if len(c.Entries) > 0 && c.Unkept {
		msg += " Another secret in it was removed from what DefenseClaw passes on and records but is not in the vault"
		if c.Err != nil {
			msg += " (" + c.errorText() + ")"
		}
		msg += "; rotate it with its issuer."
	}
	return msg
}

func (c *sandboxVaultCapture) keptMessage() string {
	point := c.point()
	if c.NotStopped {
		// A prompt the event could stop went on: it reads as one the
		// model saw.
		point.Point = connector.VaultCapturePromptSeen
	}
	if len(c.Entries) == 0 {
		if c.Err == nil {
			return "DefenseClaw found a secret in this " + point.Where() + " and removed it from what it passes on and records. " +
				"The model has seen it: the user should rotate it with its issuer. Do not use, repeat or write the value."
		}
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
	if point.Point == connector.VaultCapturePromptSeen && c.NotStopped {
		return fmt.Sprintf("DefenseClaw found a secret in this prompt and moved it into the user's vault as %s, marked exposed: "+
			"DefenseClaw is in observe mode, so the prompt was not stopped and the model may have seen it. Never repeat or write "+
			"the value. The user must rotate it with its issuer and replace it (`defenseclaw sandbox vault replace %s`) before any "+
			"sandbox can use it.", held, first)
	}
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
// entry's name and target, never a value ("-" when nothing was kept, and
// a last "+unkept" when another value was removed but not kept).
func (c *sandboxVaultCapture) header() string {
	parts := []string{c.Event}
	for i, e := range c.Entries {
		if i == maxVaultCaptureHeaderEntries {
			break
		}
		parts = append(parts, e.Name+"="+e.Target())
	}
	switch {
	case len(c.Entries) == 0:
		parts = append(parts, "-")
	case c.Unkept:
		parts = append(parts, vaultCaptureUnkeptField)
	}
	return strings.Join(parts, " ")
}

// vaultCaptureFromHeader reads a relay header the daemon set for a call of
// connectorName; anything that does not parse strictly is ignored (nil).
func vaultCaptureFromHeader(connectorName, v string) *sandboxVaultCapture {
	fields := strings.Fields(v)
	unkept := false
	if n := len(fields); n > 2 && fields[n-1] == vaultCaptureUnkeptField {
		unkept, fields = true, fields[:n-1]
	}
	if len(fields) < 2 || len(fields) > maxVaultCaptureHeaderEntries+1 {
		return nil
	}
	name := sandboxauth.CanonicalConnector(connectorName)
	if _, reads := connector.SandboxVaultCaptureEventFor(name, ""); !reads || !validVaultCaptureEventName(fields[0]) {
		return nil
	}
	c := &sandboxVaultCapture{Connector: name, Event: fields[0], Unkept: unkept}
	if len(fields) == 2 && fields[1] == "-" {
		if unkept {
			return nil
		}
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

// afterSandboxVaultCapture follows a capture up where the vault is owned:
// the alert of a vault that no longer matches its pin, and the retries of
// an exposure the hook call could not write.
func (a *APIServer) afterSandboxVaultCapture(ctx context.Context, connectorName string, c *sandboxVaultCapture) {
	if c == nil {
		return
	}
	a.alertSandboxVaultChanged(ctx, connectorName, c)
	if c.exposeErr != nil {
		a.followVaultExposure(c, c.exposeErr)
	}
}

// followVaultExposure retries, in the background, the write of an
// exposure a hook call could not make (cause wraps
// vault.ErrExposurePending or vault.ErrExposureNotRecorded), with backoff,
// for as long as the ingress runs. The pending record already keeps the
// value from any sandbox; the retry writes the exposure into the vault.
// When the exposure could not be recorded, or the retries give up, it is
// logged and audited.
func (a *APIServer) followVaultExposure(c *sandboxVaultCapture, cause error) {
	if c == nil || c.markExposed == nil || c.retrying {
		return
	}
	pending := errors.Is(cause, vault.ErrExposurePending)
	if !pending && !errors.Is(cause, vault.ErrExposureNotRecorded) {
		return
	}
	ctx := a.sandboxVaultRetryContext()
	if !pending {
		a.alertVaultExposure(ctx, c, "not_recorded")
	}
	select {
	case vaultExposureRetrySlots <- struct{}{}:
	default:
		a.alertVaultExposure(ctx, c, exposureGiveUpReason(pending, "retries_busy"))
		return
	}
	c.retrying = true
	mark, apply, delays := c.markExposed, c.applyPending, vaultExposureRetryDelays
	go func() {
		defer func() { <-vaultExposureRetrySlots }()
		for _, d := range delays {
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				fmt.Fprintf(os.Stderr, "[gateway] sandbox vault exposure retry stopped with the ingress connector=%s event=%s pending=%v\n",
					c.Connector, c.Event, pending)
				return
			case <-t.C:
			}
			err := mark(vaultCaptureRetryWait)
			if err == nil && apply != nil {
				err = apply(vaultCaptureRetryWait)
			}
			if err == nil {
				return
			}
			pending = pending || errors.Is(err, vault.ErrExposurePending)
		}
		a.alertVaultExposure(ctx, c, exposureGiveUpReason(pending, "retries_exhausted"))
	}()
}

func exposureGiveUpReason(pending bool, why string) string {
	if pending {
		return why + "_pending"
	}
	return why + "_not_recorded"
}

// alertVaultExposure logs and audits an exposure the vault has not
// written: names, never values.
func (a *APIServer) alertVaultExposure(ctx context.Context, c *sandboxVaultCapture, reason string) {
	var names []string
	for _, e := range c.Entries {
		names = append(names, e.Name)
	}
	fmt.Fprintf(os.Stderr, "[gateway] sandbox vault exposure not written connector=%s event=%s sandbox=%s reason=%s entries=%s\n",
		c.Connector, c.Event, c.Sandbox, reason, strings.Join(names, ","))
	if a == nil || a.logger == nil {
		return
	}
	severity, title := "MEDIUM", "Sandbox vault exposure is pending: no sandbox gets the value until it is written"
	if strings.HasSuffix(reason, "not_recorded") {
		severity, title = "HIGH", "Sandbox vault exposure could not be recorded: rotate the secret and replace it in the vault"
	}
	if err := a.logger.LogAlertCtx(context.WithoutCancel(ctx), sandboxVaultExposureRuleID, severity, title, map[string]any{
		"connector": c.Connector, "event": c.Event, "sandbox": c.Sandbox, "entries": names,
		"reason": reason, "rule_id": sandboxVaultExposureRuleID,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] sandbox vault exposure alert failed connector=%s: %v\n", c.Connector, err)
	}
}

// sandboxVaultRetryContext ends when the sandbox ingress stops.
func (a *APIServer) sandboxVaultRetryContext() context.Context {
	if st := a.sandboxIngressState(); st != nil {
		return st.lifeContext()
	}
	return context.Background()
}

// sandboxVaultPinRuleID is the alert of a capture refused because the vault
// does not match its pin.
const sandboxVaultPinRuleID = "sandbox_vault_pin"

// alertSandboxVaultChanged records a capture the vault refused because it
// no longer matches the seal DefenseClaw pinned: someone changed the vault
// file (its seal header, or a sealed vault replaced with a plain one).
func (a *APIServer) alertSandboxVaultChanged(ctx context.Context, connectorName string, c *sandboxVaultCapture) {
	if a == nil || a.logger == nil || c == nil || !errors.Is(c.Err, vault.ErrVaultChanged) {
		return
	}
	reason := "seal_changed"
	if errors.Is(c.Err, vault.ErrSealRemoved) {
		reason = "seal_removed"
	}
	if err := a.logger.LogAlertCtx(ctx, sandboxVaultPinRuleID, "HIGH",
		"Sandbox vault does not match its pinned seal: capture refused", map[string]any{
			"connector": connectorName, "event": c.Event, "sandbox": c.Sandbox,
			"reason": reason, "rule_id": sandboxVaultPinRuleID,
		}); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] sandbox vault pin alert failed connector=%s: %v\n", connectorName, err)
	}
}

// stops reports whether the event's answer, in action mode, is block.
func (c *sandboxVaultCapture) stops() bool { return c.point().Stop }

// applySandboxVaultCapture turns a verdict into the capture's answer in the
// configured mode, which it never overrides. Action mode: block where the
// event can stop (or the verdict blocked already); otherwise an allow is
// raised to an alert that carries the capture's message, and a confirm or
// alert is kept. Observe mode: nothing is stopped that observe mode would
// not stop; the answer says what action mode would do (would_block) and
// carries the message. A prompt the event could have stopped that goes on
// is marked exposed in the vault. Cursor's stop and subagentStop get no
// message: their only output starts a new turn.
func (a *APIServer) applySandboxVaultCapture(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	resp agentHookResponse,
	c *sandboxVaultCapture,
) agentHookResponse {
	mode := resp.Mode
	if mode == "" {
		// The mode the verdict would have had: action for a sandbox call,
		// unless a relayed call's guardrail profile sets its own.
		mode = sandboxHookMode(ctx, c.Connector, a.agentHookMode(ctx, c.Connector))
	}
	resp.Mode = mode
	switch {
	case resp.Action == "block":
		resp.RawAction = "block"
	case mode != "action":
		raw := "alert"
		if c.stops() {
			raw = "block"
		}
		if resp.RawAction != "block" {
			resp.RawAction = raw
		}
		if resp.Action == "" {
			resp.Action = "allow"
		}
		resp.WouldBlock = resp.WouldBlock || c.stops()
	case c.stops():
		resp.Action, resp.RawAction, resp.WouldBlock = "block", "block", true
	case resp.Action == "allow" || resp.Action == "" || resp.Action == "alert":
		resp.Action, resp.RawAction, resp.WouldBlock = "alert", "alert", false
	default:
		// confirm (or another non-block answer the verdict chose): kept.
		if resp.RawAction == "" || resp.RawAction == "allow" {
			resp.RawAction = resp.Action
		}
	}
	if c.Connector == "cursor" && cursorTurnRestartEvent(c.Event) && resp.Action == "block" {
		// Cursor answers a block of stop or subagentStop with a followup
		// message, which starts a new turn: never block them.
		resp.Action, resp.RawAction, resp.WouldBlock = "alert", "block", true
	}
	if c.point().Point == connector.VaultCapturePrompt {
		switch {
		case resp.Action != "block":
			a.markVaultCaptureExposed(c)
		case c.NotStopped:
			// Stored exposed for an answer that, after all, stops it: it
			// stays exposed (the stricter state), and the message says so.
			c.NotStopped = false
		}
	}
	if resp.Severity != "CRITICAL" {
		resp.Severity = "HIGH"
	}
	if req.HookEventName == "" {
		req.HookEventName = c.Event
	}
	resp = a.renderSandboxVerdict(ctx, profile, req, rawBody, payload, resp, c.message())
	if c.Connector == "cursor" && cursorTurnRestartEvent(c.Event) {
		resp.AdditionalContext = ""
		resp.HookOutput = nil
	}
	return resp
}

// markVaultCaptureExposed marks a prompt capture exposed because the
// prompt went on to the model. A capture that stored it exposed already
// (captureSandboxVault knew the answer would not stop it) writes nothing
// more; otherwise (a relayed call, whose answer the managed gateway
// chose) a write the vault could not make is recorded pending and
// retried (followVaultExposure).
func (a *APIServer) markVaultCaptureExposed(c *sandboxVaultCapture) {
	already := c.NotStopped
	c.NotStopped = true
	for i := range c.Entries {
		c.Entries[i].Exposed = true
	}
	if already || c.markExposed == nil {
		return
	}
	if err := c.markExposed(vault.CaptureWait); err != nil {
		a.followVaultExposure(c, err)
	}
}

// cursorTurnRestartEvent: Cursor's stop and subagentStop, whose only
// output (followup_message) starts a new turn.
func cursorTurnRestartEvent(event string) bool {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case "stop", "subagentstop":
		return true
	}
	return false
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
// relayed call whose secret the daemon captured, in the mode the managed
// gateway answered in: in action mode the call is stopped with the
// capture's message whatever the gateway answered (alerted where the event
// cannot stop; a managed gateway that reads VaultCaptureHeader answers
// block already, an older one does not). Its block and confirm are kept.
// The answer's other fields (delivery receipt, evaluation and agent ids)
// are kept. It returns the new body and the answer it rendered.
func (a *APIServer) relayedVaultCaptureAnswer(ctx context.Context, connectorName string, body, answer []byte, c *sandboxVaultCapture) ([]byte, agentHookResponse) {
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
	prior := agentHookResponse{}
	prior.Severity, _ = wire["severity"].(string)
	prior.Mode, _ = wire["mode"].(string)
	if action, _ := wire["action"].(string); action == "block" || action == "confirm" {
		prior.Action, prior.RawAction = action, action
	}
	if wb, _ := wire["would_block"].(bool); wb {
		prior.WouldBlock = true
	}
	resp := a.applySandboxVaultCapture(ctx, profile, req, body, payload, prior, c)
	delete(wire, "findings")
	if len(resp.HookOutput) == 0 {
		delete(wire, hookOutputFieldName(profile.Name))
		if f := strings.TrimSpace(profile.ResponseFieldName); f != "" {
			delete(wire, f)
		}
		delete(wire, "additional_context")
	}
	for k, v := range renderAgentHookResponseForProfile(profile, resp) {
		wire[k] = v
	}
	out, err := json.Marshal(wire)
	if err != nil {
		out, _ = json.Marshal(renderAgentHookResponseForProfile(profile, resp))
	}
	return append(out, '\n'), resp
}
