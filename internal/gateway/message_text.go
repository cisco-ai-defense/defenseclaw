// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The "message" tool call of OpenClaw (GAP-0177, GAP-0290..0292).
//
// OpenClaw channels name the message text differently: content, body, text,
// message, caption, or text nested in blocks and attachments. The gateway used
// to read only content and body from the call's args, and the OpenClaw plugin
// skipped the call when it found neither, so a call that carried its text
// anywhere else was never inspected. extractMessageArgs reads every string in
// the args instead. It mirrors extractMessage in
// extensions/defenseclaw/src/message-text.ts, which the plugin runs first and
// sends as the call's content (testdata/message_text_parity.json pins the two
// to the same answers). The gateway reads the args itself and its answer
// decides, so the limits and the routing values below never depend on the
// caller.
//
// A message call takes three checks, in this order:
//  1. the tool's static block list and MCP block, as for every tool call;
//  2. its text, through the message lane (rules, AI Defense, judge);
//  3. its routing values (the recipient, target, channel ...), through the
//     tool-policy lane like the destination of any other send tool.
//
// Text past the read limits is unknown, never clean: the call alerts.

const (
	// messageTextMaxBytes bounds the text returned. A longer text keeps its
	// head and its tail.
	messageTextMaxBytes = 256 * 1024
	// messageTextMaxDepth is the nesting depth below the args object.
	messageTextMaxDepth = 8
	// messageTextMaxLeaves is the number of string and number values read in
	// one call.
	messageTextMaxLeaves = 512
	// messageTextMaxNodes is the number of values of any kind walked in one
	// call, so a large array of empty objects costs a bounded walk.
	messageTextMaxNodes = 4096
)

// messageTextOverCapRuleID is the finding of a message call whose text went
// past the read limits: the part that was not read is unknown.
const messageTextOverCapRuleID = "OPENCLAW-MESSAGE-TEXT-OVER-CAP"

const messageTextOverCapReason = "message text past DefenseClaw's read limits: only part of it was inspected"

// Key names are matched with asciiLowerPreservingBytes on both sides: a full
// Unicode lowercase would read a key like "İd" as "id" in Go and not in
// JavaScript.
//
// messageTextKeys hold the message text most often. They are read first, in
// this order, ahead of the remaining keys in sorted order.
var messageTextKeys = []string{
	"content", "body", "text", "message", "caption", "subject", "title",
	"summary", "description", "html", "markdown", "blocks", "attachments",
	"voicetext", "quotetext", "presentation",
}

// messageRoutingKeys name where a message goes or how it is sent, not what it
// says. A phone number or an address in "to" would only make the content rules
// alert on every message, so a string under one of them is not scanned as
// text. It goes to the tool-policy lane as a routing value instead.
var messageRoutingKeys = map[string]bool{
	"action": true, "channel": true, "provider": true, "accountid": true,
	"account": true, "to": true, "target": true, "targets": true, "from": true,
	"recipient": true, "recipients": true, "replyto": true, "threadid": true,
	"messageid": true, "chatid": true, "id": true, "type": true, "kind": true,
	"mode": true, "format": true, "parsemode": true, "silent": true,
	"dryrun": true, "timeoutms": true, "besteffort": true, "gatewayurl": true,
	"gatewaytoken": true,
}

// messageExtract is what a message call's args hold.
type messageExtract struct {
	// Text is every string outside the routing values, joined by newlines.
	Text string
	// OverCap reports text the read limits dropped: more strings than the leaf
	// limit, a string below the depth limit, or a text past the size limit.
	OverCap bool
	// Routing holds the strings under routing keys, by dotted key path.
	Routing map[string]interface{}
}

// extractMessageArgs reads a message call's args once. Args that are not a
// JSON value yield nothing; the caller decides what an empty result means.
// Numbers are text too (a table cell, a count the message states): they are
// read as their JSON literal.
func extractMessageArgs(raw json.RawMessage) messageExtract {
	var out messageExtract
	if len(raw) == 0 {
		return out
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value interface{}
	if err := dec.Decode(&value); err != nil {
		return out
	}
	if _, err := dec.Token(); err != io.EOF {
		return out
	}
	w := messageWalk{routing: map[string]interface{}{}}
	w.walk(value, 0, "")
	text := strings.Join(w.parts, "\n")
	if len(text) > messageTextMaxBytes {
		// Head and tail, each cut at the start of a character.
		half := messageTextMaxBytes / 2
		head := half
		for head > 0 && !utf8.RuneStart(text[head]) {
			head--
		}
		tail := len(text) - half
		for tail < len(text) && !utf8.RuneStart(text[tail]) {
			tail++
		}
		text = text[:head] + "\n" + text[tail:]
		w.overCap = true
	}
	out.Text, out.OverCap = text, w.overCap
	if len(w.routing) > 0 {
		out.Routing = w.routing
	}
	return out
}

type messageWalk struct {
	parts   []string
	leaves  int
	nodes   int
	overCap bool
	routing map[string]interface{}
}

// leaf adds a string or number value to the text.
func (w *messageWalk) leaf(s string) {
	if strings.TrimSpace(s) == "" {
		return
	}
	if w.leaves >= messageTextMaxLeaves {
		w.overCap = true
		return
	}
	w.leaves++
	w.parts = append(w.parts, s)
}

func (w *messageWalk) walk(value interface{}, depth int, path string) {
	if w.nodes >= messageTextMaxNodes {
		w.overCap = w.overCap || messageHasText(value)
		return
	}
	w.nodes++
	switch v := value.(type) {
	case string:
		w.leaf(v)
	case json.Number:
		w.leaf(v.String())
	case []interface{}:
		if depth > messageTextMaxDepth {
			w.overCap = w.overCap || messageHasText(v)
			return
		}
		for _, item := range v {
			w.walk(item, depth+1, path)
		}
	case map[string]interface{}:
		if depth > messageTextMaxDepth {
			w.overCap = w.overCap || messageHasText(v)
			return
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		rank := func(k string) int {
			lower := asciiLowerPreservingBytes(k)
			for i, t := range messageTextKeys {
				if t == lower {
					return i
				}
			}
			return len(messageTextKeys)
		}
		// Keys sort by rank, then by code point (the byte order of UTF-8).
		sort.Slice(keys, func(i, j int) bool {
			if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
				return ri < rj
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			if messageRoutingKeys[asciiLowerPreservingBytes(k)] && w.routingValue(child, v[k]) {
				continue
			}
			w.walk(v[k], depth+1, child)
		}
	}
}

// routingValue files the strings of a routing key's value and reports whether
// the value held nothing else. A routing key that holds an object (a target
// with its own text) is read like any other: its strings are text and the
// routing keys inside it file their own.
func (w *messageWalk) routingValue(path string, value interface{}) bool {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			w.fileRouting(path, v)
		}
		return true
	case []interface{}:
		for _, item := range v {
			if _, nested := item.(map[string]interface{}); nested {
				return false
			}
			if _, nested := item.([]interface{}); nested {
				return false
			}
		}
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				w.fileRouting(path, s)
			}
		}
		return true
	case map[string]interface{}:
		return false
	default:
		// A number or a flag under a routing key is a control value.
		return true
	}
}

// messageHasText reports a value that holds a non-blank string or a number anywhere.
func messageHasText(value interface{}) bool {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case json.Number:
		return true
	case []interface{}:
		for _, item := range v {
			if messageHasText(item) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if messageHasText(item) {
				return true
			}
		}
	}
	return false
}

func (w *messageWalk) fileRouting(path, s string) {
	key := path
	for n := 2; ; n++ {
		if _, taken := w.routing[key]; !taken {
			break
		}
		key = path + "#" + strconv.Itoa(n)
	}
	w.routing[key] = s
}

// messageRoutingArgs is the args the tool-policy lane reads for a message
// call's routing values: the recipient, target and channel strings under
// their own keys. Nothing is left out of the call; text is read by the
// message lane.
func messageRoutingArgs(routing map[string]interface{}) json.RawMessage {
	if len(routing) == 0 {
		return nil
	}
	b, err := json.Marshal(routing)
	if err != nil {
		return nil
	}
	return b
}

// messageTextOverCapVerdict is the verdict of text the read limits dropped.
// The part that was not read is unknown, so the call alerts whatever the read
// part held; a stronger verdict from the lanes stands.
func messageTextOverCapVerdict() *ToolInspectVerdict {
	finding := RuleFinding{
		RuleID: messageTextOverCapRuleID, Title: "message text past the read limits",
		Severity: "MEDIUM", Confidence: 1.0, Tags: []string{"message-text", "unknown"},
	}
	return &ToolInspectVerdict{
		Action: "alert", Severity: "MEDIUM", Confidence: 1.0,
		Reason:           messageTextOverCapReason,
		Findings:         []string{messageTextOverCapRuleID},
		DetailedFindings: []RuleFinding{finding},
	}
}

// inspectMessageCall decides a message tool call that reached /inspect/tool.
// The args are parsed once; the text and the routing values come from them.
func (a *APIServer) inspectMessageCall(ctx context.Context, req *ToolInspectRequest) *ToolInspectVerdict {
	// A static block or an MCP block decides before any text is read.
	if v := a.toolBlockListVerdict(ctx, req, nil); v != nil {
		return v
	}
	// The gateway reads the args itself: its answer decides, whatever the
	// caller sent as content. A caller that sends no args (a hook that only
	// has the text) is read from its content.
	ex := extractMessageArgs(req.Args)
	text := ex.Text
	if text == "" {
		text = req.Content
	}
	if text == "" && !ex.OverCap {
		if args := strings.TrimSpace(string(req.Args)); args == "" || args == "null" || args == "{}" || args == "[]" {
			// Nothing to inspect: an empty call.
			return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
		}
		// Arguments with no text (GAP-0177): the tool policy reads them.
		return a.inspectToolPolicyCtx(ctx, req)
	}
	textReq := *req
	textReq.Content = text
	verdict := a.inspectMessageContent(ctx, &textReq)
	if routing := messageRoutingArgs(ex.Routing); routing != nil && !a.managedAIDOnly() {
		// The routing values are not text, but they are not skipped: a secret
		// in a recipient field or a destination the rules name is found by
		// the same lane that reads the destination of any other send tool.
		routeReq := *req
		routeReq.Args, routeReq.Content, routeReq.skipJudge = routing, "", true
		verdict = mergeToolInspectVerdicts(verdict, a.inspectToolPolicyCtx(ctx, &routeReq))
	}
	if ex.OverCap {
		verdict = mergeToolInspectVerdicts(verdict, messageTextOverCapVerdict())
	}
	return verdict
}
