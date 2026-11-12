// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func testPlan() ChartPlan {
	return ChartPlan{
		Schema: 1, Release: "dc", Namespace: "defenseclaw-system", ChartVersion: "1.0.10", AppVersion: "1.0.10",
		StoreSchema: 1, SubstrateNamespace: "ate-system", SupportedVersions: ">=1.0.0 <1.1.0",
		API:               PlanAPI{Address: "api.ate-system.svc:443", Audience: "api.ate-system.svc"},
		ActorHost:         "defenseclaw-actor.defenseclaw-system.svc",
		LauncherAtespaces: []string{"eng-payments", "eng-web"},
		WritableAtespaces: []string{"data-team", "eng-payments", "eng-web"},
		Editors:           editors,
		GlobalViewers:     editors,
		CredentialProvider: CredentialProvider{Grant: true, ConfigMap: "k8s-credential-provider-namespace-policy",
			Deployment: "k8s-credential-provider", SecretsNamespace: "defenseclaw-actor-secrets"},
		StoreStateConfigMap: "defenseclaw-store-state",
		OwnerTokenSecret:    "ate-owner", DeleteOwnerToken: true,
	}
}

type fakeAPI struct {
	atespaces map[string]bool
	policies  map[string]*AccessPolicy
	egress    map[ActorRef]*EgressPolicy
	puts      []AccessPolicy
	deleteErr map[ActorRef]error
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{atespaces: map[string]bool{"data-team": true}, policies: map[string]*AccessPolicy{},
		egress: map[ActorRef]*EgressPolicy{}, deleteErr: map[ActorRef]error{}}
}

func (f *fakeAPI) GetAtespace(_ context.Context, n string) (bool, error) { return f.atespaces[n], nil }
func (f *fakeAPI) CreateAtespace(_ context.Context, n string) error {
	if f.atespaces[n] {
		return errors.New("exists")
	}
	f.atespaces[n] = true
	return nil
}
func (f *fakeAPI) GetAccessPolicy(_ context.Context, a string) (*AccessPolicy, error) {
	if p := f.policies[a]; p != nil {
		c := *p
		return &c, nil
	}
	return nil, nil
}
func (f *fakeAPI) PutAccessPolicy(_ context.Context, p AccessPolicy) error {
	if cur := f.policies[p.Atespace]; cur != nil && (cur.UID != p.UID || cur.Version != p.Version) {
		return errors.New("precondition")
	}
	p.UID = "uid-" + p.Atespace
	p.Version++
	f.policies[p.Atespace] = &p
	f.puts = append(f.puts, p)
	return nil
}
func (f *fakeAPI) ListActors(_ context.Context, a string) ([]ActorRef, error) {
	var out []ActorRef
	for r := range f.egress {
		if a == "" || r.Atespace == a {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(x, y ActorRef) int { return strings.Compare(x.String(), y.String()) })
	return out, nil
}
func (f *fakeAPI) GetEgressPolicy(_ context.Context, r ActorRef) (*EgressPolicy, error) {
	return f.egress[r], nil
}
func (f *fakeAPI) DeleteEgressPolicy(_ context.Context, r ActorRef) error {
	if err := f.deleteErr[r]; err != nil {
		return err
	}
	f.egress[r] = nil
	return nil
}

type fakeKube struct {
	cms       map[string]*ConfigMap
	restarts  []string
	deleted   []string
	updateErr error
}

func newFakeKube() *fakeKube { return &fakeKube{cms: map[string]*ConfigMap{}} }

func (k *fakeKube) GetConfigMap(_ context.Context, ns, name string) (*ConfigMap, error) {
	if cm := k.cms[ns+"/"+name]; cm != nil {
		c := *cm
		c.Data = map[string]string{}
		for key, v := range cm.Data {
			c.Data[key] = v
		}
		return &c, nil
	}
	return nil, nil
}
func (k *fakeKube) UpdateConfigMap(_ context.Context, cm *ConfigMap) error {
	if k.updateErr != nil {
		return k.updateErr
	}
	k.cms[cm.Namespace+"/"+cm.Name] = cm
	return nil
}
func (k *fakeKube) RestartDeployment(_ context.Context, ns, name string) error {
	k.restarts = append(k.restarts, ns+"/"+name)
	return nil
}
func (k *fakeKube) DeleteSecret(_ context.Context, ns, name string) error {
	k.deleted = append(k.deleted, ns+"/"+name)
	return nil
}

func TestBootstrap(t *testing.T) {
	api, kube := newFakeAPI(), newFakeKube()
	api.policies[""] = &AccessPolicy{UID: "g", Version: 1, Bindings: []Binding{{Role: RoleOwner, Members: []string{"user:admin"}}}}
	api.policies["data-team"] = &AccessPolicy{Atespace: "data-team", UID: "d", Version: 4,
		Bindings: []Binding{{Role: RoleEditor, Members: []string{"user:dana"}}}}
	kube.cms["ate-system/k8s-credential-provider-namespace-policy"] = &ConfigMap{Namespace: "ate-system",
		Name: "k8s-credential-provider-namespace-policy", Data: map[string]string{NamespacePolicyKey: "policies:\n- atespace: team-a\n  allowedNamespaces: [ns1]\n"}}

	r, err := Bootstrap(context.Background(), testPlan(), api, kube)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"eng-payments", "eng-web"} {
		if !api.atespaces[a] {
			t.Errorf("launcher atespace %s not created", a)
		}
		if got := api.policies[a].Members(RoleEditor); len(got) != 2 {
			t.Errorf("%s editors = %v", a, got)
		}
	}
	if got := api.policies["data-team"].Members(RoleEditor); len(got) != 3 || !slices.Contains(got, "user:dana") {
		t.Errorf("data-team editors = %v", got)
	}
	if got := api.policies[""].Members(RoleViewer); len(got) != 2 {
		t.Errorf("global viewers = %v", got)
	}
	policy := kube.cms["ate-system/k8s-credential-provider-namespace-policy"].Data[NamespacePolicyKey]
	if !strings.Contains(policy, "team-a") || strings.Count(policy, "defenseclaw-actor-secrets") != 2 {
		t.Errorf("namespace policy:\n%s", policy)
	}
	if len(kube.restarts) != 1 || len(kube.deleted) != 1 || kube.deleted[0] != "defenseclaw-system/ate-owner" {
		t.Errorf("restarts %v, deleted %v", kube.restarts, kube.deleted)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "owner member") {
		t.Errorf("no note about global owners: %v", r.Notes)
	}

	// A second run changes nothing and restarts nothing.
	puts := len(api.puts)
	kube.restarts = nil
	if _, err := Bootstrap(context.Background(), testPlan(), api, kube); err != nil {
		t.Fatal(err)
	}
	if len(api.puts) != puts || len(kube.restarts) != 0 {
		t.Errorf("second bootstrap wrote %d policies, restarted %v", len(api.puts)-puts, kube.restarts)
	}
}

func TestBootstrapDoesNotCreateManagedAtespaces(t *testing.T) {
	api, kube := newFakeAPI(), newFakeKube()
	delete(api.atespaces, "data-team")
	r, err := Bootstrap(context.Background(), testPlan(), api, kube)
	if err != nil {
		t.Fatal(err)
	}
	if api.atespaces["data-team"] {
		t.Error("created a managed atespace")
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "data-team does not exist") {
		t.Errorf("notes %v", r.Notes)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "not installed") {
		t.Errorf("no note about the missing credential provider: %v", r.Notes)
	}
}

func TestPreUpgradeAndRollback(t *testing.T) {
	ctx := context.Background()
	plan := testPlan()
	kube := newFakeKube()
	if _, err := PreUpgrade(ctx, plan, []byte("x"), func([]byte) error { return errors.New("bad key") }, kube); err == nil ||
		!strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("invalid config: %v", err)
	}
	if _, err := PreUpgrade(ctx, plan, nil, nil, kube); err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	kube.cms["defenseclaw-system/defenseclaw-store-state"] = &ConfigMap{Data: StoreState{SchemaVersion: 2,
		Backup: "store-1.0.11-20261120T0101Z.db", WrittenByVersion: "1.0.11"}.Data()}
	_, err := PreRollback(ctx, plan, kube)
	var rs *ErrRollbackSchema
	if !errors.As(err, &rs) || !strings.Contains(err.Error(), "store-1.0.11-20261120T0101Z.db") {
		t.Fatalf("rollback across a schema change: %v", err)
	}
	if _, err := PreUpgrade(ctx, plan, nil, nil, kube); err == nil {
		t.Fatal("an upgrade to an older release was allowed")
	}
	plan.StoreSchema, plan.AppVersion = 2, "1.0.12"
	if _, err := PreRollback(ctx, plan, kube); err != nil {
		t.Fatalf("same schema: %v", err)
	}
	plan.AppVersion = "1.2.0"
	if _, err := PreUpgrade(ctx, plan, nil, nil, kube); !errors.Is(err, ErrSkew) {
		t.Fatalf("minor skip: %v", err)
	}
}

func TestPreDeleteRemovesOnlyDefenseClawPolicies(t *testing.T) {
	api, kube := newFakeAPI(), newFakeKube()
	plan := testPlan()
	ours := ActorRef{"eng-web", "a1"}
	fork := ActorRef{"other", "f1"}
	foreign := ActorRef{"other", "x"}
	api.egress[ours] = &EgressPolicy{Actor: ours, Hostnames: []string{plan.ActorHost, "github.com"}}
	api.egress[fork] = &EgressPolicy{Actor: fork, Hostnames: []string{plan.ActorHost + ":443"}}
	api.egress[foreign] = &EgressPolicy{Actor: foreign, Hostnames: []string{"pypi.org"}}
	api.egress[ActorRef{"eng-web", "nopolicy"}] = nil
	kube.cms["ate-system/k8s-credential-provider-namespace-policy"] = &ConfigMap{Namespace: "ate-system",
		Name: "k8s-credential-provider-namespace-policy", Data: map[string]string{NamespacePolicyKey: "policies:\n- atespace: eng-web\n  allowedNamespaces: [defenseclaw-actor-secrets]\n- atespace: team-a\n  allowedNamespaces: [ns1]\n"}}

	r, err := PreDelete(context.Background(), plan, api, kube)
	if err != nil {
		t.Fatal(err)
	}
	if api.egress[ours] != nil || api.egress[fork] != nil || api.egress[foreign] == nil {
		t.Errorf("egress after uninstall: ours=%v fork=%v foreign=%v", api.egress[ours], api.egress[fork], api.egress[foreign])
	}
	if len(r.Removed) != 2 {
		t.Errorf("removed %v", r.Removed)
	}
	policy := kube.cms["ate-system/k8s-credential-provider-namespace-policy"].Data[NamespacePolicyKey]
	if strings.Contains(policy, "eng-web") || !strings.Contains(policy, "team-a") {
		t.Errorf("namespace policy after uninstall:\n%s", policy)
	}
	if notes := strings.Join(r.Notes, "\n"); !strings.Contains(notes, "kubectl ate delete tag") || !strings.Contains(notes, "grants stay") {
		t.Errorf("no purge steps: %v", r.Notes)
	}
}

func TestPreDeleteFailsWhilePoliciesRemain(t *testing.T) {
	api, kube := newFakeAPI(), newFakeKube()
	plan := testPlan()
	stuck := ActorRef{"elsewhere", "a"}
	api.egress[stuck] = &EgressPolicy{Actor: stuck, Hostnames: []string{plan.ActorHost}}
	api.deleteErr[stuck] = errors.New("PermissionDenied")
	_, err := PreDelete(context.Background(), plan, api, kube)
	if !errors.Is(err, ErrPoliciesLeft) || !strings.Contains(err.Error(), "elsewhere/a") {
		t.Fatalf("err = %v", err)
	}
}

func TestIsDefenseClaws(t *testing.T) {
	host := "defenseclaw-actor.dc.svc"
	if !(EgressPolicy{Hostnames: []string{host}}).IsDefenseClaws(host + ".cluster.local") {
		t.Error("an FQDN actor host does not match the short rule name")
	}
	for h, want := range map[string]bool{host: true, host + ":443": true, host + ".cluster.local": true, "DefenseClaw-Actor.dc.svc.": true,
		"defenseclaw-actor.other.svc": false, "evil-" + host: false, "x.defenseclaw-actor.dc.svc": false} {
		if got := (EgressPolicy{Hostnames: []string{h}}).IsDefenseClaws(host); got != want {
			t.Errorf("%s: %v", h, got)
		}
	}
}
