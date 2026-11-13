//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// PLAN 7.3 / F3 open item: create picks the class from the profile's
// sandbox_class. A template that already meets it keeps its selector; a
// weaker one gets the class label on the actor (the template's other labels
// kept), so the actor lands on a pool of that class.
func TestSubstrateCreatePicksTheProfileSandboxClass(t *testing.T) {
	cfg := &config.Config{}
	cfg.Substrate.DefaultSandboxClass = "gvisor"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"eng":    {},
		"secure": {Sandbox: &config.SandboxAdminConfig{SandboxClass: "microvm"}},
	}
	classFor := SubstrateSandboxClassFor(cfg)
	if got := classFor("eng"); got != "gvisor" {
		t.Fatalf("eng class %q", got)
	}
	if got := classFor("secure"); got != "microvm" {
		t.Fatalf("secure class %q", got)
	}

	fake := ateapifake.New()
	pool := map[string]string{"pool": "gv"}
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"},
		WorkerSelector: &ateapi.Selector{MatchLabels: pool}})
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc-mv"},
		WorkerSelector: &ateapi.Selector{MatchLabels: map[string]string{controller.SandboxClassLabel: "microvm"}}})
	profile := "eng"
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return profile, "eng-web", nil }
		c.SandboxClass = classFor
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { return nil }}
	create := func(tmpl, name string) *ateapi.Actor {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"`+tmpl+`","connector":"claudecode","name":"`+name+`"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, rec.Code, rec.Body)
		}
		a, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", name))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// gvisor profile: the template decides, nothing is set on the actor.
	if a := create("cc", "alice-c1"); a.GetWorkerSelector() != nil {
		t.Errorf("gvisor profile set a selector: %v", a.GetWorkerSelector())
	}
	profile = "secure"
	// microvm profile, gvisor template: the class label goes on the actor.
	a := create("cc", "alice-c2")
	got := a.GetWorkerSelector().GetMatchLabels()
	if got[controller.SandboxClassLabel] != "microvm" || got["pool"] != "gv" {
		t.Errorf("selector %v, want the class label and the template's labels", got)
	}
	// microvm profile, microvm template: the template already meets it.
	if a := create("cc-mv", "alice-c3"); a.GetWorkerSelector() != nil {
		t.Errorf("a template that meets the class got a selector: %v", a.GetWorkerSelector())
	}
	// The request cannot pick the class.
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-c4","SandboxClass":"gvisor","sandbox_class":"gvisor"}`)
	if rec.Code == http.StatusCreated {
		a, _ := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-c4"))
		if a.GetWorkerSelector().GetMatchLabels()[controller.SandboxClassLabel] != "microvm" {
			t.Errorf("the request lowered the class: %v", a.GetWorkerSelector())
		}
	}
}
