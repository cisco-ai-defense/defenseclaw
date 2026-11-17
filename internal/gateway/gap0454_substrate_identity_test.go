// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0454: a Substrate actor's records name its sandbox driver (the class
// the launcher create chose) and the person's identity group (principal,
// source oidc, assurance verified); the resource names the pod's namespace
// and no claw mode.
func TestGAP0454SubstrateRecordsNameTheDriverAndThePerson(t *testing.T) {
	prevFacts, prevPrincipal := identityFactsEnabled.Load(), userPrincipalCollectionEnabled.Load()
	t.Cleanup(func() { setIdentityFactsEnabled(prevFacts); SetUserPrincipalCollectionEnabled(prevPrincipal) })
	setIdentityFactsEnabled(true)
	SetUserPrincipalCollectionEnabled(true)

	reg := registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: subUID1, Connector: "claudecode", Profile: "eng",
		SandboxClass: "microvm", Person: ownerOf(alice)}
	key, err := sandboxreg.SubstrateKey(reg.Atespace, reg.UID)
	if err != nil {
		t.Fatal(err)
	}
	reg.Key = key
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor(reg.Atespace, reg.Name, reg.UID, "actor/eng-web/alice-1", key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
	if d, _ := hookV8Substrate(ctx).Driver.Get(); d != "microvm" {
		t.Fatalf("driver %q, want microvm", d)
	}
	ctx = contextWithSubstratePerson(ctx, reg)
	id := requestIdentityFor(ctx, AgentIdentityFromContext(ctx).UserID)
	if id == nil {
		t.Fatal("no identity group for the actor's person")
	}
	attrs := id.v8()
	principal, _ := attrs.Principal.Get()
	source, _ := attrs.Source.Get()
	assurance, _ := attrs.Assurance.Get()
	if principal != "alice@example.com" || source != "oidc" || assurance != "verified" {
		t.Fatalf("identity group principal=%q source=%q assurance=%q", principal, source, assurance)
	}
	if requestIdentityFor(ctx, "someone-else") != nil {
		t.Fatal("the person's identity was put on another user's record")
	}

	t.Setenv("POD_NAMESPACE", "defenseclaw-system")
	t.Setenv(substrateClusterNameEnv, "prod-eu")
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	if got := observabilitySubstrateK8s(cfg, "POD_NAMESPACE"); got != "defenseclaw-system" {
		t.Fatalf("namespace %q", got)
	}
	if got := observabilitySubstrateK8s(cfg, substrateClusterNameEnv); got != "prod-eu" {
		t.Fatalf("cluster %q", got)
	}
	if got := observabilityClawMode(cfg); got != "" {
		t.Fatalf("a Substrate gateway names claw mode %q", got)
	}
	cfg.Substrate.Enabled = false
	if got := observabilitySubstrateK8s(cfg, "POD_NAMESPACE"); got != "" {
		t.Fatalf("a host gateway names namespace %q", got)
	}
}

// The launcher create records the class the actor runs in.
func TestGAP0454CreateRecordsTheSandboxClass(t *testing.T) {
	for _, tc := range []struct{ label, asked, want string }{
		{"", "", "gvisor"}, {"microvm", "", "microvm"}, {"", "microvm", "microvm"}, {"microvm", "gvisor", "microvm"},
	} {
		tmpl := &ateapi.ActorTemplate{}
		if tc.label != "" {
			tmpl.WorkerSelector = &ateapi.Selector{MatchLabels: map[string]string{controller.SandboxClassLabel: tc.label}}
		}
		if got := substrateEffectiveClass(tmpl, tc.asked); got != tc.want {
			t.Fatalf("template %q asked %q: class %q, want %q", tc.label, tc.asked, got, tc.want)
		}
	}
}
