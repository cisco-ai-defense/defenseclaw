// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
)

func httpsRule(host string) *ateapi.EgressRule {
	return &ateapi.EgressRule{Https: &ateapi.HttpsRule{Hostnames: []string{host}}}
}

// TestPreDeleteOverTheAteapiClient runs the uninstall step through API on
// A3's fake control API: DefenseClaw policies go, foreign ones stay.
func TestPreDeleteOverTheAteapiClient(t *testing.T) {
	plan := testPlan()
	f := ateapifake.New()
	f.PutAtespace("eng-web")
	f.PutAtespace("other")
	for _, a := range []*ateapi.Actor{
		{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "ours"}},
		{Metadata: &ateapi.ResourceMetadata{Atespace: "other", Name: "foreign"}},
		{Metadata: &ateapi.ResourceMetadata{Atespace: "other", Name: "bare"}},
	} {
		f.PutActor(a)
	}
	ctx := context.Background()
	if _, err := f.CreateActorEgressPolicy(ctx, ateapi.Ref("eng-web", "ours"), &ateapi.EgressPolicy{
		Rules: []*ateapi.EgressRule{httpsRule(plan.ActorHost), httpsRule("github.com")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateActorEgressPolicy(ctx, ateapi.Ref("other", "foreign"), &ateapi.EgressPolicy{
		Rules: []*ateapi.EgressRule{httpsRule("pypi.org")}}); err != nil {
		t.Fatal(err)
	}
	api := &API{Client: f}
	r, err := PreDelete(ctx, plan, api, newFakeKube())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Removed) != 1 || r.Removed[0] != "eng-web/ours" {
		t.Errorf("removed %v", r.Removed)
	}
	if f.Policy(ateapi.Ref("eng-web", "ours")) != nil || f.Policy(ateapi.Ref("other", "foreign")) == nil {
		t.Error("wrong policies removed")
	}
	if ok, err := api.GetAtespace(ctx, "eng-web"); !ok || err != nil {
		t.Errorf("GetAtespace = %v, %v", ok, err)
	}
	if ok, err := api.GetAtespace(ctx, "missing"); ok || err != nil {
		t.Errorf("GetAtespace(missing) = %v, %v", ok, err)
	}
}

// The bootstrap writes atespaces and access policies through ateapi.Client
// (A8's separate access connection is gone): create, then update with the
// uid and version preconditions, never naming the atespace in metadata.
func TestBootstrapOverTheAteapiClient(t *testing.T) {
	plan := testPlan()
	plan.CredentialProvider.Grant = false
	plan.DeleteOwnerToken = false
	f := ateapifake.New()
	f.PutAtespace("data-team")
	api := &API{Client: f}
	ctx := context.Background()
	r, err := Bootstrap(ctx, plan, api, newFakeKube())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Policies) == 0 {
		t.Fatal("no access policy written")
	}
	for _, ns := range []string{"eng-web", "eng-payments"} {
		if _, err := f.GetAtespace(ctx, ns); err != nil {
			t.Errorf("launcher atespace %s not created: %v", ns, err)
		}
		p, err := api.GetAccessPolicy(ctx, ns)
		if err != nil || p == nil || len(p.Members(RoleEditor)) != len(plan.Editors) {
			t.Errorf("%s policy = %+v, %v", ns, p, err)
		}
	}
	g, err := api.GetAccessPolicy(ctx, "")
	if err != nil || g == nil || len(g.Members(RoleViewer)) != len(plan.GlobalViewers) {
		t.Fatalf("global policy = %+v, %v", g, err)
	}
	// A second run updates in place (preconditions hold) and changes nothing.
	r2, err := Bootstrap(ctx, plan, api, newFakeKube())
	if err != nil || len(r2.Policies) != 0 {
		t.Fatalf("second bootstrap: %+v, %v", r2.Policies, err)
	}
	// An update with a stale version is refused, not overwritten.
	g.Bindings = append(g.Bindings, Binding{Role: RoleViewer, Members: []string{"user:x"}})
	g.Version--
	if err := api.PutAccessPolicy(ctx, *g); err == nil {
		t.Fatal("a stale access policy update was accepted")
	}
}
