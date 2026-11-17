// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// GAP-0452: Substrate's egress swaps a bound secret in after the callout
// ran, so nothing recorded its use. The callout now writes one
// log.secret.injected event per bound secret on an allowed request to a
// bound host: the secret's name, the host and the actor, never a value,
// prefix or placeholder; none for an unbound host, a blocked request or a
// profile the secret is not rendered for.
func TestCalloutRecordsAnInjectedSecretGAP0452(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Secrets = append(c.Secrets, SecretBinding{Name: "eng-only", Hosts: []string{"api.github.com"}, Header: "X-Eng-Key", Profiles: []string{"eng*"}})
	})
	ctx := context.Background()
	injected := func(r *Request) []Event {
		h.events.mu.Lock()
		h.events.events = nil
		h.events.mu.Unlock()
		h.eng.Finish(r, h.eng.DecideHeaders(ctx, r))
		h.events.mu.Lock()
		defer h.events.mu.Unlock()
		var out []Event
		for _, ev := range h.events.events {
			if ev.Event == EventSecretInjected {
				out = append(out, ev)
			}
		}
		return out
	}

	got := injected(req("eng-web", "GET", "api.github.com", "/user", "Authorization", "Bearer DC_SECRET_GITHUB"))
	names := map[string]bool{}
	for _, ev := range got {
		names[ev.Secret] = true
		if ev.Host != "api.github.com" || ev.Atespace != "eng-web" || ev.Actor != "a1" || ev.Decision != "inject" || ev.Profile != "eng" {
			t.Errorf("event %+v", ev)
		}
		b, _ := json.Marshal(ev)
		if strings.Contains(string(b), "DC_SECRET_GITHUB") || strings.Contains(string(b), "Bearer") {
			t.Errorf("the event carries the placeholder or a value: %s", b)
		}
	}
	if len(got) != 2 || !names["github-push"] || !names["eng-only"] {
		t.Fatalf("injected events %+v, want github-push and eng-only", got)
	}
	// Another profile: only the secret rendered for every profile.
	if got := injected(req("other", "GET", "github.com", "/")); len(got) != 1 || got[0].Secret != "github-push" {
		t.Errorf("profile base: %+v", got)
	}
	// An unbound host and a blocked request inject nothing.
	if got := injected(req("eng-web", "GET", "example.com", "/")); len(got) != 0 {
		t.Errorf("unbound host: %+v", got)
	}
	if got := injected(req("eng-web", "DELETE", "api.github.com", "/repos/acme/x")); len(got) != 0 {
		t.Errorf("blocked request: %+v", got)
	}
}

type personUIDs struct{}

func (personUIDs) ResolveActor(context.Context, string, string) (ActorRecord, bool, error) {
	return ActorRecord{UID: "uid-1", Profile: "eng", Person: "https://idp.example#eng1", Principal: "eng1@example.com"}, true, nil
}

// GAP-0513: log.secret.injected also names the person the actor is
// registered to, so a use of a managed secret is attributable.
func TestInjectedSecretNamesThePersonGAP0513(t *testing.T) {
	h := newHarness(t, func(_ *Config, o *Options) { o.UIDs = personUIDs{} })
	r := req("eng-web", "GET", "api.github.com", "/user", "Authorization", "Bearer DC_SECRET_GITHUB")
	h.eng.Finish(r, h.eng.DecideHeaders(context.Background(), r))
	h.events.mu.Lock()
	defer h.events.mu.Unlock()
	found := false
	for _, ev := range h.events.events {
		if ev.Event == EventSecretInjected {
			found = true
			if ev.Person != "https://idp.example#eng1" || ev.Principal != "eng1@example.com" {
				t.Errorf("event %+v does not name the person", ev)
			}
		}
	}
	if !found {
		t.Fatal("no log.secret.injected event")
	}
}
