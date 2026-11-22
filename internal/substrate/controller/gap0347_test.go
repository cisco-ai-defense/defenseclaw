// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// substrate-1 GAP-0347: an actor made outside DefenseClaw gets an attributed
// registration that names what its attested template's signed statement
// names (connector, agent version, hook contract, kit version, digest), so
// the gateway resolves its hook profile; an unattested template names none.
func TestGAP0347AttributedRegistrationNamesTheAttestedKit(t *testing.T) {
	for _, tc := range []struct {
		name string
		att  controller.Attestation
		want controller.Registration
	}{
		{"attested", controller.Attestation{Attested: true, Digest: digA, Connector: "claudecode", KitVersion: "1.0.10",
			AgentVersion: "2.1.317", HookContract: "claudecode-hooks-v2"},
			controller.Registration{Connector: "claudecode", AgentVersion: "2.1.317", HookContract: "claudecode-hooks-v2",
				KitVersion: "1.0.10", TemplateDigest: digA}},
		{"unattested", controller.Attestation{Connector: "claudecode", AgentVersion: "2.1.317"}, controller.Registration{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(_ *config.Config, o *controller.Options) { o.RequireAttestation = false })
			r.att.Default = tc.att
			a := r.actor("ci-runs", "job-1", ateapi.ActorStateRunning, "")
			r.pass()
			reg, ok, err := r.reg.Get(context.Background(), "ci-runs", a.GetMetadata().GetUid())
			if err != nil || !ok {
				t.Fatalf("registration: ok=%v err=%v", ok, err)
			}
			if reg.Source != controller.SourceAtespace || reg.Connector != tc.want.Connector || reg.AgentVersion != tc.want.AgentVersion ||
				reg.HookContract != tc.want.HookContract || reg.KitVersion != tc.want.KitVersion || reg.TemplateDigest != tc.want.TemplateDigest {
				t.Fatalf("registration %+v, want the kit of %+v", reg, tc.want)
			}
		})
	}
}

// The leader record of an attributed actor keeps them (the gateway reads it).
func TestGAP0347LeaderRecordKeepsTheAttestedKit(t *testing.T) {
	st := &leaderStore{m: map[string]registry.Registration{}}
	l := &controller.LeaderRegistry{Store: st}
	const uid = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
	in := controller.Registration{Atespace: "ci-runs", Name: "job-1", UID: uid, Source: controller.SourceAtespace,
		Connector: "claudecode", AgentVersion: "2.1.317", HookContract: "claudecode-hooks-v2", KitVersion: "1.0.10", TemplateDigest: digA}
	if err := l.Put(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got := st.m["ci-runs/"+uid]
	if !got.Attributed || got.Connector != "claudecode" || got.HarnessVersion != "2.1.317" ||
		got.HookContract != "claudecode-hooks-v2" || got.KitVersion != "1.0.10" || got.TemplateDigest != digA {
		t.Fatalf("leader record %+v", got)
	}
	back, ok, err := l.Get(context.Background(), "ci-runs", uid)
	if err != nil || !ok || back.Connector != "claudecode" || back.AgentVersion != "2.1.317" {
		t.Fatalf("read back %+v ok=%v err=%v", back, ok, err)
	}
}
