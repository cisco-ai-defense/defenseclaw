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
	"encoding/json"
	"sort"
	"strings"
)

// The text of a "message" tool call (GAP-0177).
//
// OpenClaw channels name the message text differently: content, body, text,
// message, caption, or text nested in blocks and attachments. The gateway used
// to read only content and body from the call's args, and the OpenClaw plugin
// skipped the call when it found neither, so a call that carried its text
// anywhere else was never inspected. messageTextFromArgs reads every string in
// the args instead. It mirrors extractMessageText in
// extensions/defenseclaw/src/message-text.ts, which the plugin runs first and
// sends as the call's content; this copy serves a caller that sends the args
// alone.

const (
	// messageTextMaxBytes bounds the text returned. A longer text keeps its
	// head and its tail.
	messageTextMaxBytes = 256 * 1024
	// messageTextMaxDepth is the nesting depth below the args object.
	messageTextMaxDepth = 8
	// messageTextMaxLeaves is the number of string values read in one call.
	messageTextMaxLeaves = 512
)

// messageTextKeys hold the message text most often. They are read first, in
// this order, ahead of the remaining keys in sorted order.
var messageTextKeys = []string{
	"content", "body", "text", "message", "caption", "subject", "title",
	"summary", "description", "html", "markdown", "blocks", "attachments",
}

// messageRoutingKeys name where a message goes or how it is sent, not what it
// says. A phone number or an address in "to" would only make the content rules
// alert on every message. They stay in the args the tool policy reads.
var messageRoutingKeys = map[string]bool{
	"action": true, "channel": true, "provider": true, "accountid": true,
	"account": true, "to": true, "target": true, "targets": true, "from": true,
	"recipient": true, "recipients": true, "replyto": true, "threadid": true,
	"messageid": true, "chatid": true, "id": true, "type": true, "kind": true,
	"mode": true, "format": true, "parsemode": true, "silent": true,
	"dryrun": true, "timeoutms": true, "besteffort": true, "gatewayurl": true,
	"gatewaytoken": true,
}

// messageTextFromArgs returns the text of a message call's args, or "" when
// they hold no string outside the routing keys. The caller must not read ""
// as "nothing to inspect": the call goes to the tool policy instead.
func messageTextFromArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	var parts []string
	leaves := 0
	collectMessageText(value, 0, &leaves, &parts)
	text := strings.Join(parts, "\n")
	if len(text) <= messageTextMaxBytes {
		return text
	}
	half := messageTextMaxBytes / 2
	return text[:half] + "\n" + text[len(text)-half:]
}

func collectMessageText(value interface{}, depth int, leaves *int, out *[]string) {
	switch v := value.(type) {
	case string:
		if *leaves >= messageTextMaxLeaves || strings.TrimSpace(v) == "" {
			return
		}
		*leaves++
		*out = append(*out, v)
	case []interface{}:
		if depth > messageTextMaxDepth {
			return
		}
		for _, item := range v {
			collectMessageText(item, depth+1, leaves, out)
		}
	case map[string]interface{}:
		if depth > messageTextMaxDepth {
			return
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		rank := func(k string) int {
			lower := strings.ToLower(k)
			for i, t := range messageTextKeys {
				if t == lower {
					return i
				}
			}
			return len(messageTextKeys)
		}
		sort.Slice(keys, func(i, j int) bool {
			if ri, rj := rank(keys[i]), rank(keys[j]); ri != rj {
				return ri < rj
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			if messageRoutingKeys[strings.ToLower(k)] {
				continue
			}
			collectMessageText(v[k], depth+1, leaves, out)
		}
	}
}

// messageCallHasNoText reports whether a message call reaching /inspect/tool
// carries nothing the content rules can read: no content and no string in the
// args. Such a call takes the tool policy lane instead of being allowed.
func messageCallHasNoText(req *ToolInspectRequest) bool {
	return req.Content == "" && messageTextFromArgs(req.Args) == ""
}
