// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

func expect(t *testing.T, c Check, status, contains string) {
	t.Helper()
	if c.Status != status || !strings.Contains(c.Message, contains) {
		t.Errorf("%s = %s %q, want %s containing %q", c.ID, c.Status, c.Message, status, contains)
	}
}

func TestCheckIssuer(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckIssuerUnique(o), Pass, "unique")
	o.OtherIssuers = []string{"https://idp.cluster-a.example/"}
	expect(t, CheckIssuerUnique(o), Fail, "same actor JWT issuer")
	o = healthyCluster()
	o.Issuer = "https://idp.ate-system.svc"
	expect(t, CheckIssuerUnique(o), Fail, "2 clusters")
	expect(t, CheckIssuerUnique(o), Fail, "setup --issuer")
	// GAP-0383: a shared default issuer is named, with the fix.
	o.OtherIssuers = []string{"https://idp.ate-system.svc"}
	expect(t, CheckIssuerUnique(o), Fail, "the default https://idp.ate-system.svc")
	expect(t, CheckIssuerUnique(o), Fail, "setup --issuer")
	o.Clusters, o.OtherIssuers = 1, nil
	expect(t, CheckIssuerUnique(o), Warn, "fine for one cluster")
	o.FleetUnread = 2
	expect(t, CheckIssuerUnique(o), Warn, "2 other cluster(s) of the kubeconfig could not be read")
	o.FleetUnread = 0
	o.Issuer = ""
	expect(t, CheckIssuerUnique(o), Fail, "not set")
	if CheckIssuerUnique(o).EdgeCase != "E13" {
		t.Error("edge case")
	}
}

func TestCheckBucket(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckSnapshotBucket(o), Pass, "encrypted")
	o.Bucket.Encrypted = ptr(false)
	o.Bucket.Region = "eu-west-1"
	expect(t, CheckSnapshotBucket(o), Fail, "not encrypted")
	o = healthyCluster()
	o.Bucket.PublicAccessBlocked = ptr(false)
	expect(t, CheckSnapshotBucket(o), Fail, "public access")
	o = healthyCluster()
	o.Bucket.RetentionDays = ptr(0)
	expect(t, CheckSnapshotBucket(o), Warn, "stay forever")
	o.Bucket.RetentionDays, o.Bucket.Encrypted = nil, nil
	expect(t, CheckSnapshotBucket(o), Warn, "could not be read")
	o.Bucket = nil
	expect(t, CheckSnapshotBucket(o), Skip, "no object-storage")
	o = healthyCluster()
	o.Bucket.Missing = true
	expect(t, CheckSnapshotBucket(o), Fail, "does not exist")
	o = healthyCluster()
	o.Bucket.Err = "AccessDenied"
	expect(t, CheckSnapshotBucket(o), Warn, "could not be read from here (AccessDenied)")
	o = healthyCluster()
	o.Bucket.PublicAccessBlocked, o.Bucket.Notes = nil, []string{"inherited"}
	expect(t, CheckSnapshotBucket(o), Warn, ": inherited")
	if strings.Contains(CheckSnapshotBucket(o).Message, "public access settings could not be read") {
		t.Error("a note replaces the generic could-not-read")
	}
}

func TestCheckGrants(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckOpenFGAGrants(o), Pass, "DefenseClaw's alone")
	// Someone else can edit a launcher atespace (proxy, fork outside DefenseClaw).
	o.AtespacePolicies["eng-web"].Bindings = append(o.AtespacePolicies["eng-web"].Bindings, setup.Binding{Role: setup.RoleOwner, Members: []string{"user:mallory"}})
	expect(t, CheckOpenFGAGrants(o), Fail, "1 other editor or owner")
	o = healthyCluster()
	delete(o.AtespacePolicies, "data-team")
	expect(t, CheckOpenFGAGrants(o), Fail, "managed atespace data-team")
	o = healthyCluster()
	o.GlobalPolicy = nil
	expect(t, CheckOpenFGAGrants(o), Fail, "global viewer")
	o = healthyCluster()
	o.LauncherAtespaces = append(o.LauncherAtespaces, "eng-new")
	expect(t, CheckOpenFGAGrants(o), Fail, "eng-new has no access policy")
	o = healthyCluster()
	o.GlobalPolicy.Bindings[0].Members = append(o.GlobalPolicy.Bindings[0].Members, setup.Member(dcEditors[0]))
	expect(t, CheckOpenFGAGrants(o), Warn, "global owner")
	o.PoliciesReadable = false
	expect(t, CheckOpenFGAGrants(o), Warn, "could not read")
	// GAP-0384: refused to the gateway's own ServiceAccount is a lost grant.
	o.PoliciesDenied = true
	expect(t, CheckOpenFGAGrants(o), Fail, "lacks a grant it needs")
}

func TestCheckCallout(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckCalloutRegistered(o), Pass, "headers only")
	o.BodyOptIn = ptr(true)
	expect(t, CheckCalloutRegistered(o), Pass, "bodies on request")
	if BodyMode(o) != "body" {
		t.Error("body mode")
	}
	o.ExtprocService = "security/vendor:50051"
	expect(t, CheckCalloutRegistered(o), Fail, "does not replace it")
	o.ExtprocService = ""
	expect(t, CheckCalloutRegistered(o), Fail, "not registered")
	o.OpenAPPA = true
	expect(t, CheckCalloutRegistered(o), Fail, "OpenAPPA")
}

func TestCheckRouterClients(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckRouterClients(o), Pass, "only DefenseClaw")
	o.IngressClients = append(o.IngressClients, "spiffe://cluster.local/ns/demo/sa/client")
	expect(t, CheckRouterClients(o), Warn, "1 other router client")
	o.IngressClients = o.IngressClients[1:]
	expect(t, CheckRouterClients(o), Fail, "cannot attach")
}

func TestCheckActorRoutes(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckActorListenerRoutes(o), Pass, "only actor routes")
	o.ActorRoutes = append(o.ActorRoutes, "/api/v1/substrate/actors", "/health")
	expect(t, CheckActorListenerRoutes(o), Fail, "/api/v1/substrate/actors, /health")
	o.ActorRoutes = []string{}
	expect(t, CheckActorListenerRoutes(o), Warn, "answered none of the actor routes")
	o.ActorRoutes, o.ActorRoutesNote = nil, "no port-forward"
	expect(t, CheckActorListenerRoutes(o), Warn, "could not read the actor listener's routes (no port-forward)")
	for _, p := range ActorListenerProbes {
		if strings.HasPrefix(p, "/api/v1/substrate/hook/") && !ActorRouteAllowed(p) {
			t.Errorf("probe %s is an actor route", p)
		}
	}
	for route, want := range map[string]bool{
		"/api/v1/substrate/hook/claudecode": true, "/api/v1/substrate/relay/verify": true, "/llm/bedrock/model/x": true, "/v1/traces": true,
		"/api/v1/substrate/hook/": false, "/api/v1/substrate/asks": false, "/api/v1/substrate/policy/explain": false,
		"/v1/tracesx": false, "/llm/../api/v1/substrate/actors": false, "/fleet/status": false, "/": false,
	} {
		if ActorRouteAllowed(route) != want {
			t.Errorf("ActorRouteAllowed(%s) = %v", route, !want)
		}
	}
}

func TestCheckVersionAndLabel(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckVersion(o), Pass, "tested range")
	o.SubstrateVersion = "1.1.0"
	expect(t, CheckVersion(o), Warn, "outside the tested range")
	o.SupportedVersions = "~1"
	expect(t, CheckVersion(o), Fail, "supported_versions")
	o.SubstrateVersion = ""
	expect(t, CheckVersion(o), Warn, "could not read")
	expect(t, CheckAPIAccessLabel(healthyCluster()), Pass, "may reach")
	o.NamespaceLabels = map[string]string{}
	expect(t, CheckAPIAccessLabel(o), Fail, "kubectl label namespace")
	o.NamespaceLabels = nil
	expect(t, CheckAPIAccessLabel(o), Warn, "could not read")
}

func TestHealthState(t *testing.T) {
	h := healthyReport().Health
	h.Callout.Registered = true
	if HealthState(h, nil) != Healthy {
		t.Error("healthy")
	}
	h.Leader.LeaseHeld = false
	if HealthState(h, nil) != Degraded {
		t.Error("no lease holder")
	}
	h.Leader.LeaseHeld = true
	if HealthState(h, []Check{{Status: Fail}}) != Degraded {
		t.Error("failed check")
	}
	h.Callout.Ready = 0
	if HealthState(h, nil) != Down {
		t.Error("callout down")
	}
}

// GAP-0429: a stage whose bundle no longer verifies fails, with the stage,
// the code and the fix; one that could not be checked from here warns.
func TestCheckBundleState(t *testing.T) {
	o := healthyCluster()
	expect(t, CheckBundleState(o), Pass, "1 stage(s) enforce bundles that verify")
	o.Bundles.Stages[0].State, o.Bundles.Stages[0].Problem = BundleUnverified, "signature_invalid"
	expect(t, CheckBundleState(o), Fail, "stage s-eng (b-01AAAAAAAAAAAAAAAAAAAAAAAA version 3, key acme-2026a): signature_invalid")
	expect(t, CheckBundleState(o), Fail, "fall back to config.yaml")
	o.Bundles.Managed = true
	expect(t, CheckBundleState(o), Fail, "deny-only")
	o.Bundles.Stages[0].State, o.Bundles.Note = BundleUnchecked, "the trust anchors Secret could not be read"
	expect(t, CheckBundleState(o), Warn, "could not be verified from here (the trust anchors Secret could not be read)")
	o.Bundles.Stages, o.Bundles.Note = nil, ""
	expect(t, CheckBundleState(o), Pass, "no bundle is applied")
	o.Bundles.Note = "the defenseclaw-bundles ConfigMap could not be read: forbidden"
	expect(t, CheckBundleState(o), Warn, "could not be read: forbidden")
	o.Bundles = nil
	expect(t, CheckBundleState(o), Skip, "bundles are off")
}
