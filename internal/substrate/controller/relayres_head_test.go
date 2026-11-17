// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0372: a template whose relay runs as the agent's own user (a kit image
// built before 1.0.10: USER is the agent, no relay.agent_user) is admitted,
// named once in an audit warning, and listed by doctor
// (substrate.relay_separation); a 1.0.10 kit image is not.
func TestUnseparatedTemplatesAreNamedInTheAuditAndDoctor(t *testing.T) {
	sep := kitAttest(t, nil)
	if sep.Unseparated != "" {
		t.Fatalf("a 1.0.10 kit image: %q", sep.Unseparated)
	}
	img := "reg.example.com/dc/claude@" + digA
	old := verified(digA, "1.0.9", time.Now().Add(time.Hour))
	old.Entrypoint, old.User = []string{kit.RelayBinary, "serve"}, "1000:1000"
	ta := &controller.TemplateAttestor{Verifier: fakeVerifier{by: map[string]*attest.Verified{img: old}}, Registries: []string{"reg.example.com"}}
	att, err := ta.Attest(context.Background(), &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "claude"},
		Containers: []*ateapi.Container{{Image: img}}})
	if err != nil || !att.Attested || att.Unseparated == "" {
		t.Fatalf("a 1.0.9 kit image: %+v %v", att, err)
	}

	r := newRig(t, nil)
	r.att.Default = att
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	for i := 0; i < 3; i++ {
		r.pass()
		r.clk.Add(31 * time.Second)
	}
	if r.api.Policy(ateapi.RefOf(a.GetMetadata())) == nil {
		t.Fatal("an image of the previous release is refused")
	}
	rows := r.sink.Events(controller.EventRelayUnseparated)
	if len(rows) != 1 || rows[0].Severity != controller.SeverityWarn || !strings.Contains(rows[0].Message, "template eng-web/claude") ||
		!strings.Contains(rows[0].Message, "rebuild the template") {
		t.Fatalf("audit rows: %+v", rows)
	}
	ts, err := controller.UnseparatedTemplates(context.Background(), r.api, r.att)
	status, detail, fix := controller.SeparationCheck(ts, err)
	if status != "warn" || !strings.Contains(detail, "eng-web/claude") || fix == "" {
		t.Fatalf("doctor: %s %q %q", status, detail, fix)
	}
	if status, _, _ := controller.SeparationCheck(nil, nil); status != "pass" {
		t.Fatalf("doctor with none: %s", status)
	}
}

// kitSecurityContext is the capability adjustment template publish gives a
// kit actor whose root relay starts the agent as its own user (GAP-0458).
func kitSecurityContext() *ateapi.SecurityContext {
	return &ateapi.SecurityContext{Capabilities: &ateapi.Capabilities{Add: kit.RelayCapabilitiesAdd, Drop: kit.RelayCapabilitiesDrop}}
}

// GAP-0458: Substrate gives an actor container AUDIT_WRITE, KILL and
// NET_BIND_SERVICE by default. A 1.0.10 kit image's root relay needs SETUID,
// SETGID and KILL, so its template must add SETUID and SETGID and may add
// nothing else; the kit's own adjustment (exactly SETUID, SETGID, KILL) is
// admitted. An image whose relay and agent share a user may add nothing.
func TestAdmissionGivesTheRelayItsCapabilitiesAndNoMore(t *testing.T) {
	sc := func(add, drop []string) func(*ateapi.ActorTemplate) {
		return func(m *ateapi.ActorTemplate) {
			m.Containers[0].SecurityContext = &ateapi.SecurityContext{Capabilities: &ateapi.Capabilities{Add: add, Drop: drop}}
		}
	}
	if got := kit.ActorCapabilities(kit.RelayCapabilitiesAdd, kit.RelayCapabilitiesDrop); strings.Join(got, ",") != "KILL,SETGID,SETUID" {
		t.Fatalf("the kit adjustment gives %v", got)
	}
	for name, c := range map[string]struct {
		mut func(*ateapi.ActorTemplate)
		ok  bool
	}{
		"the kit's adjustment":           {nil, true},
		"none (Substrate's default set)": {func(m *ateapi.ActorTemplate) { m.Containers[0].SecurityContext = nil }, false},
		"drop ALL, add the three":        {sc([]string{"SETUID", "SETGID", "KILL"}, []string{"ALL"}), true},
		"add SETUID only":                {sc([]string{"SETUID"}, nil), false},
		"add CHOWN too":                  {sc([]string{"SETUID", "SETGID", "CHOWN"}, nil), false},
		"add DAC_OVERRIDE":               {sc([]string{"SETUID", "SETGID", "DAC_OVERRIDE"}, nil), false},
		"drop KILL":                      {sc([]string{"SETUID", "SETGID"}, []string{"KILL"}), false},
		"the kit's, CAP_ prefixed":       {sc([]string{"CAP_SETUID", "cap_setgid"}, []string{"AUDIT_WRITE", "cap_net_bind_service"}), true},
	} {
		att := kitAttest(t, c.mut)
		if att.Attested != c.ok || (!c.ok && (!att.Allowlist || !strings.Contains(att.Reason, "security_context"))) {
			t.Errorf("%s: %+v", name, att)
		}
	}
	img := "reg.example.com/dc/claude@" + digA
	old := verified(digA, "1.0.9", time.Now().Add(time.Hour))
	old.Entrypoint, old.User = []string{kit.RelayBinary, "serve"}, "1000:1000"
	ta := &controller.TemplateAttestor{Verifier: fakeVerifier{by: map[string]*attest.Verified{img: old}}, Registries: []string{"reg.example.com"}}
	for name, sec := range map[string]*ateapi.SecurityContext{"no adjustment": nil, "the kit's adjustment": kitSecurityContext()} {
		att, err := ta.Attest(context.Background(), &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "t"},
			Containers: []*ateapi.Container{{Image: img, SecurityContext: sec}}})
		if err != nil || att.Attested != (sec == nil) {
			t.Errorf("an unseparated image, %s: %+v %v", name, att, err)
		}
	}
}
