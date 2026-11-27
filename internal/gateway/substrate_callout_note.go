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
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0505: while another callout holds Substrate's egress slot in closed
// mode, the controller gives an actor only the DefenseClaw rule, so every
// other host the agent tries fails to resolve. The agent saw only that, and
// told its person that the sandbox's DNS settings may have changed. The hook
// answers of an actor in that state carry one line naming DefenseClaw and the
// replaced callout: the model reads it (additionalContext) and, where the
// agent shows one, so does the person (systemMessage).

// substrateCalloutViewEvery is how old the hook path's view of the slot may
// get before a hook call starts a new read (the controller reads the slot
// every five seconds).
const substrateCalloutViewEvery = 5 * time.Second

// substrateCalloutView is the hook path's last read of the slot. A hook call
// never waits for a read: it takes the last one and, when that is old,
// starts one read in the background.
type substrateCalloutView struct {
	mu   sync.Mutex
	st   controller.CalloutStatus
	ok   bool
	at   time.Time
	busy bool
}

// calloutStatus is the slot as last read, without waiting.
func (st *substrateState) calloutStatus() (controller.CalloutStatus, bool) {
	if st.cfg.EgressCallout == nil {
		return controller.CalloutStatus{}, false
	}
	v := &st.calloutView
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.busy && (v.at.IsZero() || st.clock().Sub(v.at) >= substrateCalloutViewEvery) {
		v.busy = true
		go st.readCalloutView()
	}
	return v.st, v.ok
}

// readCalloutView reads the slot once for the hook path.
func (st *substrateState) readCalloutView() {
	ctx, cancel := context.WithTimeout(context.Background(), egressCalloutInfoWait)
	cs, ok := st.cfg.EgressCallout(ctx)
	cancel()
	v := &st.calloutView
	v.mu.Lock()
	v.st, v.ok, v.at, v.busy = cs, ok, st.clock(), false
	v.mu.Unlock()
}

// substrateCalloutNote is the line an actor's hook answers carry while its
// policy keeps only the DefenseClaw rule because the DefenseClaw callout does
// not hold the slot (the controller's calloutDenyOnly: closed, or open for an
// unattended run), "" otherwise. A slot that could not be read names nothing.
func substrateCalloutNote(cs controller.CalloutStatus, ok bool, reg registry.Registration) string {
	if !ok || !cs.Known || cs.Err != "" || cs.Ours {
		return ""
	}
	switch cs.FailMode {
	case controller.CalloutOff:
		return ""
	case controller.CalloutFailOpen:
		if !reg.Unattended {
			return ""
		}
	}
	what := "another egress callout holds Substrate's egress slot in place of DefenseClaw's"
	if cs.Holder == "" {
		what = "no egress callout holds Substrate's egress slot, so DefenseClaw's is not registered"
	}
	return "DefenseClaw: " + what + " (fail closed). This agent reaches only DefenseClaw: hooks and model calls work, and every " +
		"other host is refused, which shows as a host that does not resolve or a refused connection. It is not a network or DNS " +
		"fault in the agent; the cluster administrator registers the DefenseClaw callout again (defenseclaw substrate status names it)."
}

// substrateCalloutNoteField is the native answer field of the agents whose
// answer can carry the note.
var substrateCalloutNoteField = map[string]string{"claudecode": "claude_code_output", "codex": "codex_output"}

// substrateNoteAnswer adds note to the answer obj of the hook post env.
func substrateNoteAnswer(obj map[string]json.RawMessage, env substrateEnvelope, note string) bool {
	return substrateAddCalloutNote(obj, sandboxauth.CanonicalConnector(env.Connector), substrateEnvelopeEvent(env), note)
}

// substrateEnvelopeEvent is the hook event of a post: the kit's event name,
// else the payload's hook_event_name (what the agent itself sent).
func substrateEnvelopeEvent(env substrateEnvelope) string {
	if env.Event != "" {
		return env.Event
	}
	var p struct {
		Event string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(env.Payload, &p)
	return p.Event
}

// substrateAddCalloutNote adds note to the native answer of an allowed (or
// alerted) call in obj: as model context on the prompt, session start and
// tool result events, and as the person's line on the prompt and session
// start. A refusal keeps its own answer.
func substrateAddCalloutNote(obj map[string]json.RawMessage, connector, event, note string) bool {
	field := substrateCalloutNoteField[connector]
	if field == "" || note == "" {
		return false
	}
	var action string
	if json.Unmarshal(obj["action"], &action) != nil || (action != "allow" && action != "alert") {
		return false
	}
	out := map[string]any{}
	if raw := obj[field]; len(raw) > 0 && string(raw) != "null" {
		if json.Unmarshal(raw, &out) != nil || out == nil {
			return false
		}
	}
	join := func(have any, add string) string {
		if s, _ := have.(string); s != "" {
			return s + "\n" + add
		}
		return add
	}
	toModel, toPerson := false, false
	switch event {
	case "UserPromptSubmit":
		toModel, toPerson = true, true
	case "SessionStart":
		// Codex's SessionStart answer is its systemMessage (codexOutput).
		toModel, toPerson = connector == "claudecode", true
	case "PostToolUse":
		toModel = true
	case "PostToolUseFailure":
		toModel = connector == "claudecode"
	default:
		return false
	}
	if toModel {
		hso, _ := out["hookSpecificOutput"].(map[string]any)
		if hso == nil {
			hso = map[string]any{"hookEventName": event}
		}
		if name, _ := hso["hookEventName"].(string); name != event {
			return false
		}
		hso["additionalContext"] = join(hso["additionalContext"], note)
		out["hookSpecificOutput"] = hso
	}
	if toPerson {
		out["systemMessage"] = join(out["systemMessage"], note)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return false
	}
	obj[field] = b
	return true
}
