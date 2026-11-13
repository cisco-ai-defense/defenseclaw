// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// asksDirect is the store without the leader hop.
type asksDirect struct{ *asks.Store }

func (d asksDirect) OpenAsk(ctx context.Context, a asks.Ask) (asks.Ask, error) {
	return d.Store.OpenAsk(ctx, a)
}

func TestSubstrateAsksDecisionsAndExplain(t *testing.T) {
	store := asks.NewMemory()
	fake := ateapifake.New()
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}})
	_ = fake.ForeignSetPolicy(ateapi.Ref("eng-web", "alice-1"), []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"*.pypi.example.org"}}}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Asks = asksDirect{store}; c.Policies = fake })
	call := func(method, path, tok, body string) *struct {
		code int
		body map[string]any
	} {
		rec := f.do(t, f.admin, method, path, tok, body)
		out := &struct {
			code int
			body map[string]any
		}{code: rec.Code}
		_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
		return out
	}
	// The callout raises an ask for alice's actor.
	rec := f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout,
		`{"actor":{"atespace":"eng-web","name":"alice-1"},"host":"files.example.org","summary":"download","severity":"MEDIUM"}`,
		"X-DefenseClaw-Client", "substrate-extproc")
	if rec.Code != 200 {
		t.Fatalf("callout ask %d %s", rec.Code, rec.Body)
	}
	var opened map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &opened)
	id, _ := opened["id"].(string)
	// bob's actor is unattended: no ask, a deny (D12).
	rec = f.do(t, f.admin, http.MethodPost, substrateCalloutAskPath, subCallout, `{"actor":{"atespace":"eng-web","name":"bob-1"},"host":"x.example.org"}`)
	if !strings.Contains(rec.Body.String(), asks.StateDenied) {
		t.Fatalf("unattended ask %s", rec.Body)
	}
	if r := call(http.MethodGet, "/api/v1/substrate/asks", "p-bob", ""); len(r.body["asks"].([]any)) != 0 {
		t.Fatalf("bob sees %v", r.body)
	}
	if r := call(http.MethodGet, "/api/v1/substrate/asks", "p-alice", ""); len(r.body["asks"].([]any)) != 1 {
		t.Fatalf("alice asks %v", r.body)
	}
	if r := call(http.MethodPost, "/api/v1/substrate/asks/"+id, "p-bob", `{"decision":"approve"}`); r.code != http.StatusNotFound {
		t.Fatalf("bob approves alice's ask: %d", r.code)
	}
	if r := call(http.MethodPost, "/api/v1/substrate/asks/"+id, "p-alice", `{"decision":"approve","always":true}`); r.code != 200 || r.body["state"] != "approved" {
		t.Fatalf("alice approves %d %v", r.code, r.body)
	}
	if r := call(http.MethodPost, "/api/v1/substrate/asks/"+id, "p-alice", `{"decision":"deny"}`); r.code != http.StatusConflict {
		t.Fatalf("second answer %d", r.code)
	}
	// A blocked hook is a decision of its actor's person.
	f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", envelope("claudecode", map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "d1", "cwd": "/work", "tool_name": "Bash",
		"tool_input": map[string]any{"command": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}))
	var ds []asks.Decision
	for i := 0; i < 50 && len(ds) < 2; i++ {
		ds, _ = store.Decisions(context.Background(), asks.ListRequest{OwnerID: ownerOf(alice).ID()})
	}
	r := call(http.MethodGet, "/api/v1/substrate/decisions", "p-alice", "")
	if r.code != 200 {
		t.Fatalf("decisions %d", r.code)
	}
	if r := call(http.MethodGet, "/api/v1/substrate/decisions", "p-bob", ""); len(r.body["decisions"].([]any)) != 0 {
		t.Fatalf("bob sees alice's decisions %v", r.body)
	}
	// Explain: the policy in force and a host check.
	r = call(http.MethodGet, "/api/v1/substrate/policy/explain?actor=eng-web/alice-1&host=simple.pypi.example.org", "p-alice", "")
	host, _ := r.body["host"].(map[string]any)
	if r.code != 200 || host["allowed"] != true || r.body["profile"] != "eng" {
		t.Fatalf("explain %d %v", r.code, r.body)
	}
	r = call(http.MethodGet, "/api/v1/substrate/policy/explain?actor=eng-web/alice-1&host=evil.example.com", "p-alice", "")
	if host, _ := r.body["host"].(map[string]any); host["allowed"] != false {
		t.Fatalf("explain other host %v", r.body)
	}
	if r := call(http.MethodGet, "/api/v1/substrate/policy/explain?actor=eng-web/alice-1", "p-bob", ""); r.code != http.StatusNotFound {
		t.Fatalf("bob explains alice's actor: %d", r.code)
	}
}

// The real create flow over the control API: create SUSPENDED, write the
// registration, ensure the policy, resume; a refusal deletes the actor.
func TestSubstrateCreateOverTheControlAPI(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	var ensured []string
	refuse := false
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(ctx context.Context, atespace, name string) error {
		a, err := fake.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			return err
		}
		if _, ok, _ := f.regs.Get(ctx, atespace, a.GetMetadata().GetUid()); !ok {
			return errors.New("no registration before the policy")
		}
		if a.GetStatus().GetState() != ateapi.ActorStateSuspended {
			return errors.New("resumed before the policy")
		}
		ensured = append(ensured, name)
		if refuse {
			return ErrSubstrateActorRefused
		}
		return nil
	}}
	st.cfg.Lookup = identity.ActorLookupFunc(func(ctx context.Context, atespace, name string) (identity.LiveActor, error) {
		a, err := fake.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			return identity.LiveActor{}, identity.ErrActorNotFound
		}
		return identity.LiveActor{UID: a.GetMetadata().GetUid(), State: identity.ActorState(strings.TrimPrefix(a.GetStatus().GetState().String(), "ACTOR_STATE_"))}, nil
	})
	// Found live on E1: a create without a profile takes the caller's.
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-9"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	a, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-9"))
	if err != nil || a.GetStatus().GetState() != ateapi.ActorStateRunning || len(ensured) != 1 {
		t.Fatalf("after create %v %v %v", a, err, ensured)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"cc","connector":"claudecode","name":"alice-9"}`); rec.Code != http.StatusConflict {
		t.Fatalf("same name %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"other/cc","connector":"claudecode"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("template in another atespace %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"cc"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("no connector %d", rec.Code)
	}
	refuse = true
	rec = f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"cc","connector":"claudecode","name":"alice-10"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("refused create %d %s", rec.Code, rec.Body)
	}
	if _, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-10")); !ateapi.IsNotFound(err) {
		t.Fatalf("refused actor kept: %v", err)
	}
	// A generated name is a DNS label from the principal.
	refuse = false
	rec = f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"cc","connector":"claudecode"}`)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if name, _ := out["name"].(string); rec.Code != http.StatusCreated || !strings.HasPrefix(name, "alice-") || !substrateActorNameRE.MatchString(name) {
		t.Fatalf("generated name %d %v", rec.Code, out)
	}
	// Delete goes through the control API and leaves a tombstone.
	if rec := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/actors/eng-web/alice-9", "p-alice", ""); rec.Code != 200 {
		t.Fatalf("delete %d %s", rec.Code, rec.Body)
	}
	if _, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-9")); !ateapi.IsNotFound(err) {
		t.Fatalf("deleted actor %v", err)
	}
}
