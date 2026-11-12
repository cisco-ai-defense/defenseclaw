// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// ManagementContract is the management agent contract the documents follow
// (packaging/mdm/contract/management-agent.md); it moves with the CLI's
// --version-json management_contract.
const ManagementContract = 1

// The health states, worst last.
const (
	Healthy  = "healthy"
	Degraded = "degraded"
	Down     = "down"
)

// Cluster identifies the cluster. The issuer leaves the cluster only as a
// digest, so a fleet can compare issuers (E13) without the URL.
type Cluster struct {
	Name                      string `json:"cluster_name"`
	Namespace                 string `json:"namespace"`
	IssuerSHA256              string `json:"issuer_sha256"`
	IssuerDefault             bool   `json:"issuer_default"`
	SubstrateVersion          string `json:"substrate_version,omitempty"`
	SubstrateVersionSupported bool   `json:"substrate_version_supported"`
	SupportedVersions         string `json:"supported_versions"`
}

// Replicas counts the pods of a component.
type Replicas struct {
	Desired int `json:"desired"`
	Ready   int `json:"ready"`
}

// Leader is the gateway leader and its store.
type Leader struct {
	Ready       bool `json:"ready"`
	LeaseHeld   bool `json:"lease_held"`
	StoreSchema int  `json:"store_schema,omitempty"`
}

// Controller is the controller and how far behind Substrate it is.
type Controller struct {
	Desired    int  `json:"desired"`
	Ready      int  `json:"ready"`
	LagSeconds *int `json:"lag_seconds,omitempty"`
}

// Callout is the egress callout and its registration.
type Callout struct {
	Desired    int    `json:"desired"`
	Ready      int    `json:"ready"`
	Registered bool   `json:"registered"`
	BodyMode   string `json:"body_mode"`
}

// Health is the state of every component.
type Health struct {
	State      string     `json:"state"`
	Gateway    Replicas   `json:"gateway"`
	Leader     Leader     `json:"leader"`
	Controller Controller `json:"controller"`
	Callout    Callout    `json:"callout"`
}

// Atespace is the policy state of one atespace DefenseClaw writes in.
type Atespace struct {
	Name       string `json:"atespace"`
	Launcher   bool   `json:"launcher"`
	Actors     int    `json:"actors"`
	Policies   int    `json:"policies"`
	Drift      int    `json:"drift"`
	Conflicts  int    `json:"conflicts"`
	Unattested int    `json:"unattested"`
}

// Inventory counts actors and templates across the cluster.
type Inventory struct {
	Actors              int `json:"actors"`
	Running             int `json:"running"`
	Suspended           int `json:"suspended"`
	Templates           int `json:"templates"`
	UnattestedTemplates int `json:"unattested_templates"`
	ForeignActors       int `json:"foreign_actors"`
}

// Activity is the last window's activity and spend (stream 10 usage), in
// integers so it forwards. The whole member is absent when usage is not
// reported.
type Activity struct {
	WindowSeconds int   `json:"window_seconds"`
	HookDecisions int   `json:"hook_decisions"`
	Blocked       int   `json:"blocked"`
	ModelRequests int   `json:"model_requests"`
	CostMicroUSD  int64 `json:"cost_micro_usd"`
}

// Batch is one unattended batch.
type Batch struct {
	BatchID   string `json:"batch_id"`
	Tasks     int    `json:"tasks"`
	Running   int    `json:"running"`
	Succeeded int    `json:"succeeded"`
	Failed    int    `json:"failed"`
}

// StatusDocument is `defenseclaw substrate status --json`.
type StatusDocument struct {
	SchemaVersion      int        `json:"schema_version"`
	Command            string     `json:"command"`
	ManagementContract int        `json:"management_contract"`
	ProductVersion     string     `json:"product_version"`
	GeneratedAt        string     `json:"generated_at"`
	Cluster            Cluster    `json:"cluster"`
	Health             Health     `json:"health"`
	Atespaces          []Atespace `json:"atespaces"`
	Inventory          Inventory  `json:"inventory"`
	Activity           *Activity  `json:"activity,omitempty"`
	Batches            []Batch    `json:"batches"`
	Checks             []Check    `json:"checks"`
}

// VerifyDocument is `defenseclaw substrate verify --json`: the checks and
// one verdict, for a fleet gate. OK is false when any check fails.
type VerifyDocument struct {
	SchemaVersion      int     `json:"schema_version"`
	Command            string  `json:"command"`
	ManagementContract int     `json:"management_contract"`
	ProductVersion     string  `json:"product_version"`
	GeneratedAt        string  `json:"generated_at"`
	Cluster            Cluster `json:"cluster"`
	OK                 bool    `json:"ok"`
	Checks             []Check `json:"checks"`
}

// Report is what the CLI collected for a status document beyond Observed.
type Report struct {
	ProductVersion string
	Now            time.Time
	Health         Health
	Atespaces      []Atespace
	Inventory      Inventory
	Activity       *Activity
	Batches        []Batch
}

// ClusterOf builds the cluster member from what was observed.
func ClusterOf(o Observed) Cluster {
	supported, _ := setup.InRange(o.SubstrateVersion, o.SupportedVersions)
	return Cluster{
		Name:                      o.ClusterName,
		Namespace:                 o.Namespace,
		IssuerSHA256:              IssuerDigest(o.Issuer),
		IssuerDefault:             o.Issuer == "" || IsDefaultIssuer(o.Issuer),
		SubstrateVersion:          o.SubstrateVersion,
		SubstrateVersionSupported: o.SubstrateVersion != "" && supported,
		SupportedVersions:         o.SupportedVersions,
	}
}

// HealthState is the state the replica counts and checks give: down when
// no gateway or callout replica is ready, degraded when a component is
// short or a check fails.
func HealthState(h Health, checks []Check) string {
	if h.Gateway.Ready == 0 || (h.Callout.Registered && h.Callout.Ready == 0) {
		return Down
	}
	if h.Gateway.Ready < h.Gateway.Desired || !h.Leader.Ready || !h.Leader.LeaseHeld || h.Controller.Ready == 0 ||
		h.Callout.Ready < h.Callout.Desired || !h.Callout.Registered {
		return Degraded
	}
	for _, c := range checks {
		if c.Status == Fail {
			return Degraded
		}
	}
	return Healthy
}

// BuildStatus assembles the status document. Lists are never null, and the
// atespaces are sorted by name, so equal states print equal documents.
func BuildStatus(o Observed, r Report) StatusDocument {
	checks := RunChecks(o)
	h := r.Health
	h.Callout.Registered = o.ExtprocService == setup.CalloutService(o.Namespace, o.CalloutPort) && !o.OpenAPPA
	h.Callout.BodyMode = BodyMode(o)
	h.State = HealthState(h, checks)
	atespaces := append([]Atespace{}, r.Atespaces...)
	sort.Slice(atespaces, func(i, j int) bool { return atespaces[i].Name < atespaces[j].Name })
	batches := append([]Batch{}, r.Batches...)
	sort.Slice(batches, func(i, j int) bool { return batches[i].BatchID < batches[j].BatchID })
	return StatusDocument{
		SchemaVersion:      1,
		Command:            "status",
		ManagementContract: ManagementContract,
		ProductVersion:     r.ProductVersion,
		GeneratedAt:        r.Now.UTC().Format(time.RFC3339),
		Cluster:            ClusterOf(o),
		Health:             h,
		Atespaces:          atespaces,
		Inventory:          r.Inventory,
		Activity:           r.Activity,
		Batches:            batches,
		Checks:             checks,
	}
}

// BuildVerify assembles the verify document.
func BuildVerify(o Observed, productVersion string, now time.Time) VerifyDocument {
	checks := RunChecks(o)
	ok := true
	for _, c := range checks {
		if c.Status == Fail {
			ok = false
		}
	}
	return VerifyDocument{
		SchemaVersion:      1,
		Command:            "verify",
		ManagementContract: ManagementContract,
		ProductVersion:     productVersion,
		GeneratedAt:        now.UTC().Format(time.RFC3339),
		Cluster:            ClusterOf(o),
		OK:                 ok,
		Checks:             checks,
	}
}

// ExitCode is verify's exit code: 0 when every check passed or warned, 1
// when one failed (exit-codes.md: 1 is "checks failed").
func (v VerifyDocument) ExitCode() int {
	if v.OK {
		return 0
	}
	return 1
}
