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
