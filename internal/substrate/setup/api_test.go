// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
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
	if err := api.CreateAtespace(ctx, "x"); !errors.Is(err, errNoAccess) {
		t.Errorf("CreateAtespace without access: %v", err)
	}
}
