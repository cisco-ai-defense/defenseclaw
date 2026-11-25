// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// gap0505Post sends one hook post of reg through the envelope middleware,
// whose connector handler answers answer, and returns the answer the kit
// gets.
func gap0505Post(t *testing.T, st *substrateState, reg registry.Registration, event, answer string) map[string]json.RawMessage {
	t.Helper()
	h := substrateEnvelopeMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	}))
	ctx := context.WithValue(context.Background(), substrateRegistrationKey{}, reg)
	ctx = withSubstrateRoute(ctx, substrateActorRoute{class: sandboxauth.RouteHook, connector: reg.Connector})
	body := envelope(reg.Connector, map[string]any{"hook_event_name": event, "prompt": "curl https://github.com"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, substrateHookPrefix+reg.Connector, strings.NewReader(body)).WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d %s", event, rec.Code, rec.Body.String())
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &obj); err != nil {
		t.Fatalf("%s: answer %s: %v", event, rec.Body.String(), err)
	}
	return obj
}

func gap0505Native(t *testing.T, obj map[string]json.RawMessage, field string) (model, person string) {
	t.Helper()
	var out struct {
		HSO struct {
			Name    string `json:"hookEventName"`
			Context string `json:"additionalContext"`
			Watch   []any  `json:"watchPaths"`
		} `json:"hookSpecificOutput"`
		SystemMessage string `json:"systemMessage"`
	}
	if raw := obj[field]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %s: %v", field, raw, err)
		}
	}
	return out.HSO.Context, out.SystemMessage
}

// GAP-0505 (J32 ours-then-other, closed mode): with another callout in
// Substrate's egress slot the actor reaches only DefenseClaw, and the
// interactive agent told its person "the sandbox's network or DNS settings
// may have changed": no hook answer named the cause. Now an actor's prompt,
// session start and tool result answers carry one line naming DefenseClaw
// and the replaced callout (the model's context, and the person's line on
// the prompt and session start). A refusal keeps its answer, and nothing is
// added while the DefenseClaw callout holds the slot, in open mode for an
// interactive agent, or while the slot cannot be read.
func TestGAP0505HookAnswerNamesTheReplacedCallout(t *testing.T) {
	other := controller.CalloutStatus{Known: true, Holder: "default/other-callout:9443", FailMode: controller.CalloutFailClosed}
	interactive := registry.Registration{Atespace: "eng-web", Name: "sv18i-1", UID: subUID1, Connector: "claudecode", Profile: "eng"}
	task := interactive
	task.Unattended = true
	codex := interactive
	codex.Connector = "codex"
	for _, tc := range []struct {
		name   string
		cs     controller.CalloutStatus
		reg    registry.Registration
		event  string
		answer string
		field  string
		// wantModel / wantPerson: the note in additionalContext / systemMessage.
		wantModel, wantPerson bool
	}{
		{"prompt closed", other, interactive, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", true, true},
		{"prompt alert keeps its context", other, interactive, "UserPromptSubmit",
			`{"action":"alert","claude_code_output":{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"DefenseClaw observed a HIGH finding"}}}`,
			"claude_code_output", true, true},
		{"session start keeps watchPaths", other, interactive, "SessionStart",
			`{"action":"allow","claude_code_output":{"hookSpecificOutput":{"hookEventName":"SessionStart","watchPaths":["/w"]}}}`, "claude_code_output", true, true},
		{"tool result", other, interactive, "PostToolUse", `{"action":"allow"}`, "claude_code_output", true, false},
		{"none registered", controller.CalloutStatus{Known: true, FailMode: controller.CalloutFailClosed}, interactive, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", true, true},
		{"open unattended", controller.CalloutStatus{Known: true, Holder: "x/y:1", FailMode: controller.CalloutFailOpen}, task, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", true, true},
		{"codex prompt", other, codex, "UserPromptSubmit", `{"action":"allow"}`, "codex_output", true, true},
		{"codex session start", other, codex, "SessionStart", `{"action":"allow"}`, "codex_output", false, true},
		// Nothing added.
		{"pre tool", other, interactive, "PreToolUse", `{"action":"allow"}`, "claude_code_output", false, false},
		{"refusal", other, interactive, "UserPromptSubmit", `{"action":"block","reason":"no","claude_code_output":{"decision":"block","reason":"no"}}`, "claude_code_output", false, false},
		{"ours", controller.CalloutStatus{Known: true, Ours: true, Holder: "dc/dc:9443", FailMode: controller.CalloutFailClosed}, interactive, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", false, false},
		{"open interactive", controller.CalloutStatus{Known: true, Holder: "x/y:1", FailMode: controller.CalloutFailOpen}, interactive, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", false, false},
		{"off", controller.CalloutStatus{Known: true, Holder: "x/y:1", FailMode: controller.CalloutOff}, interactive, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", false, false},
		{"unknown", controller.CalloutStatus{Err: "forbidden", FailMode: controller.CalloutFailClosed}, interactive, "UserPromptSubmit", `{"action":"allow"}`, "claude_code_output", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubstrateFixture(t)
			st := f.api.substrateState()
			st.cfg.EgressCallout = func(context.Context) (controller.CalloutStatus, bool) { return tc.cs, true }
			st.readCalloutView()
			obj := gap0505Post(t, st, tc.reg, tc.event, tc.answer)
			model, person := gap0505Native(t, obj, tc.field)
			for _, c := range []struct {
				where, text string
				want        bool
			}{{"additionalContext", model, tc.wantModel}, {"systemMessage", person, tc.wantPerson}} {
				has := strings.Contains(c.text, "DefenseClaw: ") && strings.Contains(c.text, "egress slot") &&
					strings.Contains(c.text, "reaches only DefenseClaw") && strings.Contains(c.text, "not a network or DNS fault")
				if has != c.want {
					t.Errorf("%s carries the callout note: %v, want %v: %q", c.where, has, c.want, c.text)
				}
				if strings.Contains(c.text, tc.cs.Holder) && tc.cs.Holder != "" {
					t.Errorf("%s names the other callout %q", c.where, tc.cs.Holder)
				}
			}
			if strings.Contains(tc.name, "keeps its context") && !strings.Contains(model, "DefenseClaw observed a HIGH finding") {
				t.Errorf("the finding's context was lost: %q", model)
			}
			if strings.Contains(tc.name, "watchPaths") && !strings.Contains(string(obj[tc.field]), `"watchPaths":["/w"]`) {
				t.Errorf("SessionStart lost its watchPaths: %s", obj[tc.field])
			}
			if tc.name == "refusal" && string(obj["action"]) != `"block"` {
				t.Errorf("the refusal changed: %s", obj["action"])
			}
		})
	}
}

// GAP-0505: the hook path never waits for the slot read. With a read that
// does not answer, a hook call takes the last view (none yet) at once and
// starts only one read.
func TestGAP0505HookPathNeverWaitsForTheSlotRead(t *testing.T) {
	f := newSubstrateFixture(t)
	st := f.api.substrateState()
	release := make(chan struct{})
	reads := make(chan struct{}, 8)
	st.cfg.EgressCallout = func(ctx context.Context) (controller.CalloutStatus, bool) {
		reads <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return controller.CalloutStatus{Known: true, Holder: "x/y:1", FailMode: controller.CalloutFailClosed}, true
	}
	reg := registry.Registration{Atespace: "eng-web", Name: "a-1", UID: subUID1, Connector: "claudecode", Profile: "eng"}
	start := time.Now()
	for range 3 {
		obj := gap0505Post(t, st, reg, "UserPromptSubmit", `{"action":"allow"}`)
		if model, _ := gap0505Native(t, obj, "claude_code_output"); model != "" {
			t.Fatalf("a note before any read: %q", model)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("three hook calls took %s behind a slot read that does not answer", d)
	}
	close(release)
	<-reads
	select {
	case <-reads:
		t.Fatal("more than one slot read in flight")
	case <-time.After(100 * time.Millisecond):
	}
}
