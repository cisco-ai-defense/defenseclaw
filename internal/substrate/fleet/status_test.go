// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// compile compiles the contract schemas. contracttest.Dir is relative to a
// package directory directly under internal/, and this one is one deeper.
func compile(t *testing.T) contracttest.Schemas {
	t.Helper()
	t.Chdir("..")
	return contracttest.Compile(t)
}

var dcEditors = []string{"system:serviceaccount:defenseclaw-system:defenseclaw-gateway",
	"system:serviceaccount:defenseclaw-system:defenseclaw-controller"}

func ptr[T any](v T) *T { return &v }

// healthyCluster is a cluster where every check passes.
func healthyCluster() Observed {
	editors := make([]string, len(dcEditors))
	for i, e := range dcEditors {
		editors[i] = setup.Member(e)
	}
	return Observed{
		ClusterName: "dc-substrate-e1", Namespace: "defenseclaw-system",
		SubstrateVersion: "v1.0.0", SupportedVersions: ">=1.0.0 <1.1.0",
		Issuer: "https://idp.cluster-a.example", SubstrateNamespace: "ate-system",
		OtherIssuers: []string{"https://idp.cluster-b.example"}, Clusters: 2,
		Bucket: &Bucket{Location: "s3://snapshots/e1/", Encrypted: ptr(true), PublicAccessBlocked: ptr(true),
			RetentionDays: ptr(30), Region: "us-east-1", ClusterRegion: "us-east-1"},
		GlobalPolicy: &setup.AccessPolicy{Bindings: []setup.Binding{{Role: setup.RoleOwner, Members: []string{"user:admin"}},
			{Role: setup.RoleViewer, Members: editors}}},
		AtespacePolicies: map[string]*setup.AccessPolicy{
			"eng-web":   {Atespace: "eng-web", Bindings: []setup.Binding{{Role: setup.RoleEditor, Members: editors}, {Role: setup.RoleViewer, Members: []string{"user:carol"}}}},
			"data-team": {Atespace: "data-team", Bindings: []setup.Binding{{Role: setup.RoleEditor, Members: append([]string{"user:dana"}, editors...)}}},
		},
		LauncherAtespaces: []string{"eng-web"}, WritableAtespaces: []string{"data-team", "eng-web"},
		Editors: dcEditors, GlobalViewers: dcEditors, PoliciesReadable: true,
		ExtprocService: "defenseclaw-system/defenseclaw-callout:9443", CalloutPort: 9443,
		IngressClients:  []string{setup.IngressClientID("defenseclaw-system")},
		ActorRoutes:     []string{"/api/v1/substrate/hook/{connector}", "/api/v1/substrate/notify/{connector}", "/api/v1/substrate/inspect/{connector}", "/llm/{provider}", "/v1/logs", "/v1/metrics", "/v1/traces"},
		NamespaceLabels: map[string]string{APIAccessLabel: "true"},
	}
}

func healthyReport() Report {
	return Report{
		ProductVersion: "1.0.10", Now: time.Date(2026, 11, 13, 15, 4, 5, 0, time.UTC),
		Health: Health{Gateway: Replicas{2, 2}, Leader: Leader{Ready: true, LeaseHeld: true, StoreSchema: 1},
			Controller: Controller{Desired: 2, Ready: 2, LagSeconds: ptr(1)}, Callout: Callout{Desired: 2, Ready: 2}},
		Atespaces: []Atespace{{Name: "eng-web", Launcher: true, Actors: 3, Policies: 3}, {Name: "data-team", Actors: 1, Policies: 1}},
		Inventory: Inventory{Actors: 4, Running: 1, Suspended: 3, Templates: 2},
		Activity:  &Activity{WindowSeconds: 3600, HookDecisions: 120, Blocked: 2, ModelRequests: 40, CostMicroUSD: 1250000},
		Batches:   []Batch{{BatchID: "b-2", Tasks: 50, Running: 10, Succeeded: 38, Failed: 2}, {BatchID: "b-1", Tasks: 1, Succeeded: 1}},
	}
}

func TestStatusDocumentMatchesTheContract(t *testing.T) {
	s := compile(t)
	doc := BuildStatus(healthyCluster(), healthyReport())
	for _, c := range doc.Checks {
		if c.Status != Pass {
			t.Errorf("check %s = %s: %s", c.ID, c.Status, c.Message)
		}
	}
	if doc.Health.State != Healthy || !doc.Health.Callout.Registered || doc.Atespaces[0].Name != "data-team" || doc.Batches[0].BatchID != "b-1" {
		t.Errorf("status %+v", doc)
	}
	got := s.ValidateValue(t, "substrate-status.schema.json", doc)
	if got["cluster"].(map[string]any)["issuer_sha256"] != IssuerDigest("https://idp.cluster-a.example") {
		t.Error("issuer digest")
	}
	if raw, _ := json.Marshal(doc); strings.Contains(string(raw), "idp.cluster-a.example") {
		t.Error("the status document carries the issuer URL")
	}
	// A degraded, minimal document validates too: no activity, empty lists,
	// unread values.
	o := Observed{Namespace: "defenseclaw-system", SupportedVersions: ">=1.0.0 <1.1.0", CalloutPort: 9443}
	min := BuildStatus(o, Report{ProductVersion: "1.0.10", Now: time.Unix(0, 0)})
	if min.Health.State != Down || min.Atespaces == nil || min.Batches == nil {
		t.Errorf("minimal %+v", min)
	}
	min.Cluster.Name = "kind"
	s.ValidateValue(t, "substrate-status.schema.json", min)
}

func TestVerifyDocumentMatchesTheContract(t *testing.T) {
	s := compile(t)
	ok := BuildVerify(healthyCluster(), "1.0.10", time.Unix(1, 0))
	if !ok.OK || ok.ExitCode() != 0 {
		t.Errorf("verify %+v", ok)
	}
	s.ValidateValue(t, "substrate-verify.schema.json", ok)
	o := healthyCluster()
	o.ExtprocService = "security/vendor:50051"
	bad := BuildVerify(o, "1.0.10", time.Unix(1, 0))
	if bad.OK || bad.ExitCode() != 1 {
		t.Errorf("verify with another callout: %+v", bad)
	}
	s.ValidateValue(t, "substrate-verify.schema.json", bad)
}

func TestMembersMatchTheSchemas(t *testing.T) {
	t.Chdir("..")
	for name, typ := range map[string]reflect.Type{
		"substrate-status.schema.json":                                     reflect.TypeOf(StatusDocument{}),
		"substrate-verify.schema.json":                                     reflect.TypeOf(VerifyDocument{}),
		"substrate-status.schema.json#/$defs/cluster":                      reflect.TypeOf(Cluster{}),
		"substrate-status.schema.json#/$defs/replicas":                     reflect.TypeOf(Replicas{}),
		"substrate-status.schema.json#/$defs/health":                       reflect.TypeOf(Health{}),
		"substrate-status.schema.json#/$defs/health/properties/leader":     reflect.TypeOf(Leader{}),
		"substrate-status.schema.json#/$defs/health/properties/controller": reflect.TypeOf(Controller{}),
		"substrate-status.schema.json#/$defs/health/properties/callout":    reflect.TypeOf(Callout{}),
		"substrate-status.schema.json#/$defs/atespace":                     reflect.TypeOf(Atespace{}),
		"substrate-status.schema.json#/$defs/inventory":                    reflect.TypeOf(Inventory{}),
		"substrate-status.schema.json#/$defs/activity":                     reflect.TypeOf(Activity{}),
		"substrate-status.schema.json#/$defs/batch":                        reflect.TypeOf(Batch{}),
		"substrate-status.schema.json#/$defs/check":                        reflect.TypeOf(Check{}),
		"substrate-verify.schema.json#/$defs/check":                        reflect.TypeOf(Check{}),
	} {
		contracttest.RequireMembers(t, name, typ)
	}
}

func TestCheckIDsMatchTheSchema(t *testing.T) {
	got := RunChecks(Observed{})
	if len(got) != len(CheckIDs) {
		t.Fatalf("%d checks, %d ids", len(got), len(CheckIDs))
	}
	for i, c := range got {
		if c.ID != CheckIDs[i] || c.Message == "" {
			t.Errorf("check %d = %+v", i, c)
		}
	}
}
