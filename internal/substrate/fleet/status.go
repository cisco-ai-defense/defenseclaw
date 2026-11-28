// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
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
	Ready bool `json:"ready"`
	// Desired is the leader's replica count, for doctor's components row
	// (GAP-0593); not part of the status document.
	Desired     int  `json:"-"`
	LeaseHeld   bool `json:"lease_held"`
	StoreSchema int  `json:"store_schema,omitempty"`
}

// Controller is the controller's replicas.
type Controller struct {
	Desired int `json:"desired"`
	Ready   int `json:"ready"`
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

// Atespace is one launcher or managed atespace and its actors. Conflicts
// counts its agents in policy_conflict; nil (left out) when they were not
// counted (policy_conflicts.reason says why), never a 0 then (GAP-0398).
type Atespace struct {
	Name      string         `json:"atespace"`
	Launcher  bool           `json:"launcher"`
	Actors    int            `json:"actors"`
	States    map[string]int `json:"states"`
	Conflicts *int           `json:"conflicts,omitempty"`
}

// Inventory counts every actor and template in the cluster.
type Inventory struct {
	Actors    int            `json:"actors"`
	States    map[string]int `json:"states"`
	Templates int            `json:"templates"`
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
	Inventory          *Inventory `json:"inventory,omitempty"`
	// PolicyConflicts counts the agents in policy_conflict per atespace
	// (GAP-0398). Always set; optional in the contract.
	PolicyConflicts *PolicyConflicts `json:"policy_conflicts,omitempty"`
	// Bundles are the signed policy bundles in force, one per stage; left
	// out when substrate.bundles is off (GAP-0432).
	Bundles []BundleStage `json:"bundles,omitempty"`
	Checks  []Check       `json:"checks"`
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
	// PolicyConflicts: as in the status document (GAP-0398).
	PolicyConflicts *PolicyConflicts `json:"policy_conflicts,omitempty"`
	// Bundles: as in the status document (GAP-0432).
	Bundles []BundleStage `json:"bundles,omitempty"`
	Checks  []Check       `json:"checks"`
}

// Report is what the CLI collected for a status document beyond Observed.
// Inventory is nil, and Atespaces empty, when the actors could not be read;
// InventoryNote says why (for the text output only: it is free text).
type Report struct {
	ProductVersion string
	Now            time.Time
	Health         Health
	Atespaces      []Atespace
	Inventory      *Inventory
	InventoryNote  string
	// GlobOverlaps are the atespaces DefenseClaw does not manage that a
	// glob of a match.substrate assignment meets (GAP-0506), one line each.
	// They are warnings for the text output and doctor only: the contract
	// documents (status/verify --json) keep their fixed check list.
	GlobOverlaps []string
	// ActorAtespaces are the atespaces of the actors read (one per actor).
	ActorAtespaces []string
	// AssignmentGroups are the match.groups of each profile assignment of
	// config.yaml, by profile (GAP-0568).
	AssignmentGroups []ProfileGroups
}

// ProfileGroups is one profile assignment's match.groups.
type ProfileGroups struct {
	Profile string
	Groups  []string
}

// groupIDRE is a Keycloak group id (a UUID): the form a groups claim
// carries only when the issuer maps group ids, not names or paths.
var groupIDRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// groupForm is "id" for a Keycloak group id, "path" for a full group path
// (/parent/name), "name" otherwise.
func groupForm(g string) string {
	switch g = strings.TrimSpace(g); {
	case groupIDRE.MatchString(g):
		return "id"
	case strings.HasPrefix(g, "/"):
		return "path"
	}
	return "name"
}

// hostGroupForm reports a blank value or a host-side group form (DOMAIN\name
// or a SID such as S-1-5-21-...), which the sign-in token never carries.
func hostGroupForm(g string) bool {
	g = strings.TrimSpace(g)
	return g == "" || strings.Contains(g, `\`) || sidRE.MatchString(g)
}

var sidRE = regexp.MustCompile(`(?i)^S-1-[0-9]+(-[0-9]+)+$`)

// groupFormWords says a form in words.
func groupFormWords(form string) string {
	switch form {
	case "id":
		return "group ids"
	case "path":
		return "group paths"
	}
	return "group names"
}

// GroupFormMismatches returns one warning per profile assignment whose
// match.groups cannot match the groups the sign-in server sends
// (GAP-0568): an assignment that mixes Keycloak group ids with names or
// paths (a group claim carries one form, so the other values match nobody),
// and, when tokenGroups (the groups of a signed-in token) are known, an
// assignment written in another form than the token's. The line names the
// profile and the form the claim really carries.
func GroupFormMismatches(assignments []ProfileGroups, tokenGroups []string) []string {
	tokenForm, example := "", ""
	for _, g := range tokenGroups {
		if strings.TrimSpace(g) == "" {
			continue // a blank claim value says nothing of the form
		}
		if example == "" {
			example = strings.TrimSpace(g)
		}
		f := groupForm(g)
		if tokenForm == "" {
			tokenForm = f
		} else if tokenForm != f {
			tokenForm = "mixed"
		}
	}
	var out []string
	for _, a := range assignments {
		forms := map[string][]string{}
		for _, g := range a.Groups {
			if hostGroupForm(g) {
				// DOMAIN\name and SID values match the host's groups (an
				// AD-joined launcher), not the token's: no form to compare.
				continue
			}
			forms[groupForm(g)] = append(forms[groupForm(g)], strings.TrimSpace(g))
		}
		switch {
		case len(forms) > 1:
			out = append(out, fmt.Sprintf("profile %s matches groups in more than one form (%s): a group claim carries one form, so some of these values match nobody; write every group in the form your sign-in server sends", a.Profile, groupFormList(forms)))
		case len(forms) == 1 && tokenForm != "" && tokenForm != "mixed":
			for form := range forms {
				if form != tokenForm {
					out = append(out, fmt.Sprintf("profile %s matches %s (%s), but the sign-in server sends %s (such as %s), so it matches nobody and its members get the default profile; write them as %s",
						a.Profile, groupFormWords(form), strings.Join(forms[form], ", "), groupFormWords(tokenForm), example, groupFormWords(tokenForm)))
				}
			}
		}
	}
	return out
}

func groupFormList(forms map[string][]string) string {
	var parts []string
	for _, f := range []string{"id", "name", "path"} {
		if vs, ok := forms[f]; ok {
			parts = append(parts, groupFormWords(f)+": "+strings.Join(vs, ", "))
		}
	}
	return strings.Join(parts, "; ")
}

// GlobOverlaps returns, for each atespace that holds actors and that
// DefenseClaw neither created (launcher) nor lists by name, a line naming
// the match.substrate globs that meet it: the profile does not apply there (E3), as the
// controller's sandbox.warning says, so an operator who meant it to must
// list the atespace by name. The result is sorted.
func GlobOverlaps(actorAtespaces, launcher, exact, globs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range actorAtespaces {
		if seen[a] || slices.Contains(launcher, a) || slices.Contains(exact, a) {
			continue
		}
		seen[a] = true
		var hit []string
		for _, g := range globs {
			if ok, err := path.Match(g, a); err == nil && ok {
				hit = append(hit, g)
			}
		}
		if len(hit) > 0 {
			out = append(out, fmt.Sprintf("atespace %s matches the glob %s but DefenseClaw neither created nor lists it, so the profile "+
				"does not apply there: list it by name in match.substrate.atespaces, or delete it if it should not exist", a, strings.Join(hit, ", ")))
		}
	}
	sort.Strings(out)
	return out
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
	return healthState(h, checks, false)
}

// healthState is HealthState; calloutOff (substrate.extproc.enabled: false,
// GAP-0496) means an unregistered callout is the operator's choice, which
// the callout check reports as a warning, not a degraded cluster.
func healthState(h Health, checks []Check, calloutOff bool) string {
	if h.Gateway.Ready == 0 || (h.Callout.Registered && h.Callout.Ready == 0) {
		return Down
	}
	if h.Gateway.Ready < h.Gateway.Desired || !h.Leader.Ready || !h.Leader.LeaseHeld || h.Controller.Ready == 0 ||
		h.Callout.Ready < h.Callout.Desired || (!h.Callout.Registered && !calloutOff) {
		return Degraded
	}
	for _, c := range checks {
		if c.Status == Fail {
			return Degraded
		}
	}
	return Healthy
}

// BuildStatus assembles the status document. Lists and state maps are never
// null, and the atespaces are sorted by name, so equal states print equal
// documents.
func BuildStatus(o Observed, r Report) StatusDocument {
	checks := RunChecks(o)
	h := r.Health
	h.Callout.Registered = o.ExtprocService == setup.CalloutService(o.Namespace, o.CalloutPort) && !o.OpenAPPA
	h.Callout.BodyMode = BodyMode(o)
	h.State = healthState(h, checks, o.ExtprocOff)
	atespaces := append([]Atespace{}, r.Atespaces...)
	sort.Slice(atespaces, func(i, j int) bool { return atespaces[i].Name < atespaces[j].Name })
	var counts map[string]int
	if conflictsRead(o) {
		counts = conflictCounts(o)
	}
	for i := range atespaces {
		if atespaces[i].States == nil {
			atespaces[i].States = map[string]int{}
		}
		atespaces[i].Conflicts = nil
		if counts != nil {
			n := counts[atespaces[i].Name]
			atespaces[i].Conflicts = &n
		}
	}
	var inv *Inventory
	if r.Inventory != nil {
		c := *r.Inventory
		if c.States == nil {
			c.States = map[string]int{}
		}
		inv = &c
	}
	return StatusDocument{
		SchemaVersion:      1,
		Command:            "status",
		ManagementContract: ManagementContract,
		ProductVersion:     r.ProductVersion,
		GeneratedAt:        r.Now.UTC().Format(time.RFC3339),
		Cluster:            ClusterOf(o),
		Health:             h,
		Atespaces:          atespaces,
		Inventory:          inv,
		PolicyConflicts:    policyConflicts(o),
		Bundles:            bundleStages(o),
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
		PolicyConflicts:    policyConflicts(o),
		Bundles:            bundleStages(o),
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
