// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// Status of one check.
const (
	Pass = "pass"
	Warn = "warn"
	Fail = "fail"
	Skip = "skip"
)

// The check ids (substrate-status.schema.json#/$defs/check).
const (
	CheckSubstrateVersion = "substrate_version"
	CheckIssuer           = "issuer_unique"
	CheckBucket           = "snapshot_bucket"
	CheckGrants           = "openfga_grants"
	CheckCallout          = "callout_registered"
	CheckIngressClients   = "ingress_clients"
	CheckActorRoutes      = "actor_service_routes"
	CheckAPIAccess        = "api_access_label"
	CheckActorKeys        = "actor_keys"
)

// CheckIDs lists every check in the order doctor prints them.
var CheckIDs = []string{CheckSubstrateVersion, CheckIssuer, CheckActorKeys, CheckBucket, CheckGrants, CheckCallout,
	CheckIngressClients, CheckActorRoutes, CheckAPIAccess}

// Check is one result. Message is for the admin (kept on the cluster);
// EdgeCase names the plan edge case it guards, when there is one.
type Check struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	EdgeCase string `json:"edge_case,omitempty"`
}

func result(id, status, edge, format string, args ...any) Check {
	return Check{ID: id, Status: status, EdgeCase: edge, Message: fmt.Sprintf(format, args...)}
}

// Bucket is what the CLI read of the Substrate snapshot bucket, with the
// object store's own CLI (aws or gcloud) as the administrator. A nil
// pointer member is "could not be read".
type Bucket struct {
	// Location is the install file's storage.snapshotLocation.
	Location string
	// Err is set when the bucket could not be read at all (no CLI, no
	// credentials, access denied); Missing when the store says it does
	// not exist.
	Err     string
	Missing bool
	// Notes are warnings the reader found that no member below holds.
	Notes               []string
	Encrypted           *bool
	PublicAccessBlocked *bool
	// RetentionDays is the lifecycle expiry of snapshot objects; 0 means none.
	RetentionDays *int
	Region        string
	ClusterRegion string
}

// Observed is what the CLI read from the cluster and the config.
type Observed struct {
	ClusterName string
	Namespace   string

	SubstrateVersion  string
	SupportedVersions string

	// Issuer is substrate.identity.issuer; SubstrateNamespace the
	// namespace Substrate runs in (its default issuer is
	// https://idp.<namespace>.svc). OtherIssuers are the issuers of the
	// other clusters in the fleet config; Clusters counts them all.
	Issuer             string
	SubstrateNamespace string
	OtherIssuers       []string
	Clusters           int

	// The actor token key set (GAP-0194). KeysURL is the effective
	// substrate.identity.keys_url. Keys is the result of reading it: nil
	// when it was not read (KeysNote says why), else the signing key
	// count, 0 with KeysErr when it did not answer. ServedIssuer is the
	// issuer the idp's discovery document names (what ate-api-server puts
	// in iss; "" when not read), InstallIssuer the install file's
	// actorJWT.issuer ("" when unset).
	KeysURL       string
	Keys          *int
	KeysErr       string
	KeysNote      string
	ServedIssuer  string
	InstallIssuer string

	// Bucket is nil when the install file names no object-storage
	// snapshot location (s3:// or gs://), for example kind with a local
	// store.
	Bucket *Bucket

	// The policies the CLI read as the gateway's ServiceAccount (nil when
	// absent), and the grants the release needs (the chart's plan: the
	// launcher atespaces from the config, the managed ones from
	// --managed-atespaces, the chart's ServiceAccounts).
	GlobalPolicy      *setup.AccessPolicy
	AtespacePolicies  map[string]*setup.AccessPolicy
	LauncherAtespaces []string
	WritableAtespaces []string
	Editors           []string
	GlobalViewers     []string
	// PoliciesReadable is false when the access policies could not be
	// read; PoliciesNote says why.
	PoliciesReadable bool
	PoliciesNote     string

	// The SubstrateInstall settings in effect: the callout service, the
	// router clients, and whether the body opt-in is on (nil when the
	// setting does not exist).
	ExtprocService string
	CalloutPort    int
	IngressClients []string
	BodyOptIn      *bool
	OpenAPPA       bool

	// ActorRoutes are the probed paths (ActorListenerProbes) the actor
	// listener answered with anything but 404, read through a port-forward
	// to the actor Service; nil when not read (ActorRoutesNote says why).
	ActorRoutes     []string
	ActorRoutesNote string

	NamespaceLabels map[string]string
}

// DefaultIssuer is Substrate's actor JWT issuer when actorJWT.issuer is unset.
func DefaultIssuer(substrateNamespace string) string {
	if substrateNamespace == "" {
		substrateNamespace = "ate-system"
	}
	return "https://idp." + substrateNamespace + ".svc"
}

// IssuerDigest is the SHA-256 hex of an issuer, how fleet documents carry it.
func IssuerDigest(issuer string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(issuer, "/")))
	return hex.EncodeToString(sum[:])
}

// IsDefaultIssuer reports whether issuer has the shape every cluster gets by
// default (https://idp.<namespace>.svc).
func IsDefaultIssuer(issuer string) bool {
	return defaultIssuerShape.MatchString(strings.TrimRight(issuer, "/"))
}

var defaultIssuerShape = regexp.MustCompile(`^https://idp\.[a-z0-9-]+\.svc(\.cluster\.local)?$`)

// RunChecks runs every check over o.
func RunChecks(o Observed) []Check {
	return []Check{
		CheckVersion(o), CheckIssuerUnique(o), CheckActorKeysVerify(o), CheckSnapshotBucket(o), CheckOpenFGAGrants(o),
		CheckCalloutRegistered(o), CheckRouterClients(o), CheckActorListenerRoutes(o), CheckAPIAccessLabel(o),
	}
}

// CheckVersion: the Substrate release is inside substrate.supported_versions.
func CheckVersion(o Observed) Check {
	if o.SubstrateVersion == "" {
		return result(CheckSubstrateVersion, Warn, "", "could not read the Substrate version (ate-api-server image tag)")
	}
	ok, err := setup.InRange(o.SubstrateVersion, o.SupportedVersions)
	switch {
	case err != nil:
		return result(CheckSubstrateVersion, Fail, "", "substrate.supported_versions: %v", err)
	case !ok:
		return result(CheckSubstrateVersion, Warn, "", "Substrate %s is outside the tested range %s; upgrade DefenseClaw "+
			"or Substrate (one minor at a time) before relying on it", o.SubstrateVersion, o.SupportedVersions)
	}
	return result(CheckSubstrateVersion, Pass, "", "Substrate %s is in the tested range %s", o.SubstrateVersion, o.SupportedVersions)
}

// CheckIssuerUnique: with more than one cluster each needs its own actor JWT
// issuer, or an actor token of one cluster verifies in another (E13).
func CheckIssuerUnique(o Observed) Check {
	if o.Issuer == "" {
		return result(CheckIssuer, Fail, "E13", "substrate.identity.issuer is not set")
	}
	digest := IssuerDigest(o.Issuer)
	for _, other := range o.OtherIssuers {
		if IssuerDigest(other) == digest {
			return result(CheckIssuer, Fail, "E13", "another cluster uses the same actor JWT issuer: an actor token from one "+
				"cluster would verify in the other. Give each cluster its own issuer (setup --issuer) and the same value in "+
				"substrate.identity.issuer")
		}
	}
	if IsDefaultIssuer(o.Issuer) || o.Issuer == DefaultIssuer(o.SubstrateNamespace) {
		if o.Clusters > 1 {
			return result(CheckIssuer, Fail, "E13", "%d clusters are configured and this one uses the default issuer %s, "+
				"which every cluster has; set a unique issuer per cluster", o.Clusters, o.Issuer)
		}
		return result(CheckIssuer, Warn, "E13", "the default issuer %s is fine for one cluster; set a unique one before adding another", o.Issuer)
	}
	return result(CheckIssuer, Pass, "E13", "the actor JWT issuer is unique to this cluster")
}

// CheckActorKeysVerify: the gateway verifies actor tokens with the keys at
// the keys URL and compares iss with substrate.identity.issuer as a
// string. The keys URL must answer, and Substrate must sign with that
// issuer, or every actor token is refused (GAP-0194).
func CheckActorKeysVerify(o Observed) Check {
	// The messages name settings, never the issuer or the keys URL: the
	// status document leaves the cluster (the issuer only as a digest).
	refused := ": every actor token is refused, so no hook or model call of any agent runs"
	switch {
	case o.Issuer == "":
		return result(CheckActorKeys, Skip, "", "substrate.identity.issuer is not set")
	case o.InstallIssuer != "" && o.InstallIssuer != o.Issuer:
		return result(CheckActorKeys, Fail, "", "the install file's actorJWT.issuer differs from substrate.identity.issuer%s; "+
			"set the same value in both", refused)
	case o.Keys == nil:
		return result(CheckActorKeys, Warn, "", "the keys URL (substrate.identity.keys_url) was not read from here (%s); "+
			"defenseclaw substrate doctor --cluster checks it from the gateway", o.KeysNote)
	case *o.Keys == 0:
		return result(CheckActorKeys, Fail, "", "the keys URL (substrate.identity.keys_url) does not answer (%s)%s; set it "+
			"(chart value substrate.actorKeys.url) to the idp Service key set", o.KeysErr, refused)
	case o.ServedIssuer == "":
		return result(CheckActorKeys, Warn, "", "the keys URL answers (%d keys), but the idp discovery document could not be "+
			"read to compare the issuer Substrate signs with", *o.Keys)
	case o.ServedIssuer != o.Issuer:
		return result(CheckActorKeys, Fail, "", "Substrate signs actor tokens with another issuer than substrate.identity.issuer%s; "+
			"run ate-setup deploy with the issuer from setup --issuer, or fix the config", refused)
	}
	return result(CheckActorKeys, Pass, "", "the keys URL answers (%d keys) and Substrate signs actor tokens with substrate.identity.issuer",
		*o.Keys)
}

// CheckSnapshotBucket: snapshots hold everything an actor had in memory and
// on disk, so the bucket must be encrypted, private, expiring and in the
// cluster's region (E10).
func CheckSnapshotBucket(o Observed) Check {
	b := o.Bucket
	switch {
	case b == nil:
		return result(CheckBucket, Skip, "E10", "the install file names no object-storage snapshot location "+
			"(storage.snapshotLocation s3:// or gs://)")
	case b.Missing:
		return result(CheckBucket, Fail, "E10", "snapshot bucket %s does not exist: actors cannot be suspended", b.Location)
	case b.Err != "":
		return result(CheckBucket, Warn, "E10", "snapshot bucket %s could not be read from here (%s)", b.Location, b.Err)
	}
	var fails []string
	warns := append([]string{}, b.Notes...)
	switch {
	case b.Encrypted == nil:
		warns = append(warns, "encryption could not be read")
	case !*b.Encrypted:
		fails = append(fails, "not encrypted at rest")
	}
	switch {
	case b.PublicAccessBlocked == nil && len(b.Notes) == 0:
		warns = append(warns, "public access settings could not be read")
	case b.PublicAccessBlocked == nil:
		// A note says why (Cloud Storage: inherited).
	case !*b.PublicAccessBlocked:
		fails = append(fails, "public access is not blocked")
	}
	switch {
	case b.RetentionDays == nil:
		warns = append(warns, "the lifecycle rules could not be read")
	case *b.RetentionDays == 0:
		warns = append(warns, "no lifecycle expiry: snapshots of deleted actors stay forever")
	}
	if b.Region != "" && b.ClusterRegion != "" && b.Region != b.ClusterRegion {
		warns = append(warns, fmt.Sprintf("in %s while the cluster is in %s", b.Region, b.ClusterRegion))
	}
	switch {
	case len(fails) > 0:
		return result(CheckBucket, Fail, "E10", "snapshot bucket %s: %s", b.Location, strings.Join(append(fails, warns...), "; "))
	case len(warns) > 0:
		return result(CheckBucket, Warn, "E10", "snapshot bucket %s: %s", b.Location, strings.Join(warns, "; "))
	}
	return result(CheckBucket, Pass, "E10", "snapshot bucket %s is encrypted, private, expiring and in the cluster's region", b.Location)
}

// CheckOpenFGAGrants: DefenseClaw is the only editor (and no one owns) the
// launcher atespaces, an editor in the managed ones, and a global viewer
// (E2, E3, E17).
func CheckOpenFGAGrants(o Observed) Check {
	if !o.PoliciesReadable {
		return result(CheckGrants, Warn, "E2", "could not read the access policies as the gateway's ServiceAccount (%s)",
			o.PoliciesNote)
	}
	editors, viewers := members(o.Editors), members(o.GlobalViewers)
	var problems []string
	for _, a := range o.LauncherAtespaces {
		p := o.AtespacePolicies[a]
		if p == nil {
			problems = append(problems, fmt.Sprintf("launcher atespace %s has no access policy (missing, or not bootstrapped)", a))
			continue
		}
		if !containsAll(p.Members(setup.RoleEditor), editors) {
			problems = append(problems, fmt.Sprintf("%s: DefenseClaw is not an editor", a))
		}
		foreign := len(p.Members(setup.RoleOwner))
		for _, m := range p.Members(setup.RoleEditor) {
			if !slices.Contains(editors, m) {
				foreign++
			}
		}
		if foreign > 0 {
			problems = append(problems, fmt.Sprintf("%s: %d other editor or owner member(s) can create, fork or suspend "+
				"actors there outside DefenseClaw", a, foreign))
		}
	}
	for _, a := range o.WritableAtespaces {
		if slices.Contains(o.LauncherAtespaces, a) {
			continue
		}
		if p := o.AtespacePolicies[a]; p == nil || !containsAll(p.Members(setup.RoleEditor), editors) {
			problems = append(problems, fmt.Sprintf("managed atespace %s: DefenseClaw is not an editor, so it cannot write "+
				"egress policies there", a))
		}
	}
	if o.GlobalPolicy == nil || !containsAll(o.GlobalPolicy.Members(setup.RoleViewer), viewers) {
		problems = append(problems, "DefenseClaw is not a global viewer: inventory and live actor checks fail")
	}
	if len(problems) > 0 {
		return result(CheckGrants, Fail, "E2", "%s. Run the chart bootstrap (bootstrap.ownerTokenSecret) or apply "+
			"`defenseclaw substrate setup --print-access-policies` as a global owner", strings.Join(problems, "; "))
	}
	if o.GlobalPolicy != nil {
		for _, m := range o.GlobalPolicy.Members(setup.RoleOwner) {
			if slices.Contains(editors, m) || slices.Contains(viewers, m) {
				return result(CheckGrants, Warn, "E3", "a DefenseClaw ServiceAccount is a global owner; it needs only viewer")
			}
		}
	}
	managed := "the managed and global grants are in place"
	if len(o.WritableAtespaces) <= len(o.LauncherAtespaces) {
		managed = "the global grant is in place (no managed atespaces were named with --managed-atespaces)"
	}
	return result(CheckGrants, Pass, "E2", "launcher atespaces are DefenseClaw's alone; %s", managed)
}

func members(principals []string) []string {
	out := make([]string, len(principals))
	for i, p := range principals {
		out[i] = setup.Member(p)
	}
	return out
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// CheckCalloutRegistered: atenet-egress sends allowed requests to the
// DefenseClaw callout, and no other callout holds the slot (D10).
func CheckCalloutRegistered(o Observed) Check {
	want := setup.CalloutService(o.Namespace, o.CalloutPort)
	switch {
	case o.OpenAPPA:
		return result(CheckCallout, Fail, "", "OpenAPPA holds Substrate's one additional callout, so DefenseClaw's egress "+
			"checks do not run. DefenseClaw does not replace another callout; turn OpenAPPA off, or keep it and set "+
			"substrate.extproc.enabled: false (no egress feeds, DLP or MCP body checks at egress)")
	case o.ExtprocService == "":
		return result(CheckCallout, Fail, "", "the egress callout is not registered: run `defenseclaw substrate setup` and "+
			"ate-setup with its overlay")
	case o.ExtprocService != want:
		return result(CheckCallout, Fail, "", "egress goes to another callout (%s); DefenseClaw does not replace it. "+
			"Remove it, or keep it and set substrate.extproc.enabled: false", o.ExtprocService)
	}
	mode := "headers only"
	if o.BodyOptIn != nil && *o.BodyOptIn {
		mode = "bodies on request: MCP and listed hosts, 1 MiB"
	}
	return result(CheckCallout, Pass, "", "the DefenseClaw callout is registered (%s)", mode)
}

// BodyMode is the callout body mode the status reports.
func BodyMode(o Observed) string {
	switch {
	case o.BodyOptIn == nil:
		return "headers_only"
	case *o.BodyOptIn:
		return "body"
	}
	return "headers_only"
}

// CheckRouterClients: the gateway is a router client (launchers attach
// through it), and any other client, which reaches every actor, is counted
// (E2).
func CheckRouterClients(o Observed) Check {
	ours := setup.IngressClientID(o.Namespace)
	if !slices.Contains(o.IngressClients, ours) {
		return result(CheckIngressClients, Fail, "E2", "the gateway is not in ingressAllowedSPIFFEIDs: launchers cannot attach to actors")
	}
	if others := len(o.IngressClients) - 1; others > 0 {
		return result(CheckIngressClients, Warn, "E2", "%d other router client(s) can reach every actor, also in launcher "+
			"atespaces, without DefenseClaw; remove the ones you do not need", others)
	}
	return result(CheckIngressClients, Pass, "E2", "only DefenseClaw reaches actors through the router")
}

// actorRoutePrefixes and actorRouteExact are the only routes the actor
// listener may serve (PLAN 6.1): hooks, notify and inspect, the model proxy,
// OTLP, and the relay's session check.
var actorRoutePrefixes = []string{
	"/api/v1/substrate/hook/", "/api/v1/substrate/notify/", "/api/v1/substrate/inspect/", "/llm/",
}

var actorRouteExact = []string{"/v1/logs", "/v1/metrics", "/v1/traces", "/api/v1/substrate/relay/verify"}

// ActorListenerProbes are the paths verify asks the actor listener for,
// without an actor token: one per actor route (they answer 401), and one
// per route of the admin listener and the host gateway API (they must
// answer 404, PLAN 6.1). A GET without a token reaches no handler. There is
// no "/llm/../" probe: the listener sends every /llm/ path to the model
// proxy, which has no admin route, so it answers 401 there by design.
var ActorListenerProbes = []string{
	"/api/v1/substrate/hook/claudecode", "/api/v1/substrate/notify/codex", "/api/v1/substrate/inspect/tool",
	"/llm/bedrock", "/v1/logs", "/v1/metrics", "/v1/traces", "/api/v1/substrate/relay/verify",
	"/", "/health", "/status", "/api/v1/substrate/info", "/api/v1/substrate/actors", "/api/v1/substrate/actors/a/b",
	"/api/v1/substrate/actors/a/b/attach", "/api/v1/substrate/session-cert", "/api/v1/substrate/batches",
	"/api/v1/substrate/usage", "/api/v1/substrate/doctor", "/api/v1/substrate/asks", "/api/v1/substrate/decisions",
	"/api/v1/substrate/policy/explain", "/api/v1/substrate/secrets", "/api/v1/substrate/bundle/status",
	"/api/v1/substrate/fleet/verify", "/api/v1/substrate/signin", "/api/v1/fleet/", "/api/v1/claude-code/hook",
	"/api/v1/codex/notify", "/api/v1/admin/shutdown",
}

// ActorRouteAllowed reports whether route may be on the actor listener.
func ActorRouteAllowed(route string) bool {
	if slices.Contains(actorRouteExact, route) {
		return true
	}
	for _, p := range actorRoutePrefixes {
		if strings.HasPrefix(route, p) && len(route) > len(p) && !strings.Contains(route, "..") {
			return true
		}
	}
	return false
}

// CheckActorListenerRoutes: the actor Service serves actor routes only;
// admin, launcher, fleet and bundle APIs are never reachable from an actor
// (E1, D15).
func CheckActorListenerRoutes(o Observed) Check {
	if o.ActorRoutes == nil {
		return result(CheckActorRoutes, Warn, "E1", "could not read the actor listener's routes (%s)", o.ActorRoutesNote)
	}
	var extra []string
	for _, r := range o.ActorRoutes {
		if !ActorRouteAllowed(r) {
			extra = append(extra, r)
		}
	}
	if len(extra) > 0 {
		return result(CheckActorRoutes, Fail, "E1", "the actor listener serves routes actors must not reach: %s",
			strings.Join(extra, ", "))
	}
	if len(o.ActorRoutes) == 0 {
		return result(CheckActorRoutes, Warn, "E1", "the actor Service answered none of the actor routes: it may not be "+
			"DefenseClaw's actor listener")
	}
	return result(CheckActorRoutes, Pass, "E1", "the actor listener serves only actor routes (%d of %d probed paths answer)",
		len(o.ActorRoutes), len(ActorListenerProbes))
}

// APIAccessLabel is the namespace label Substrate's NetworkPolicy admits to
// ate-api-server.
const APIAccessLabel = "ate.dev/api-access"

// CheckAPIAccessLabel: the release namespace may reach ate-api-server.
func CheckAPIAccessLabel(o Observed) Check {
	if o.NamespaceLabels == nil {
		return result(CheckAPIAccess, Warn, "", "could not read the labels of namespace %s", o.Namespace)
	}
	if o.NamespaceLabels[APIAccessLabel] != "true" {
		return result(CheckAPIAccess, Fail, "", "namespace %s lacks %s=true, so Substrate's NetworkPolicy drops its calls "+
			"to ate-api-server: kubectl label namespace %s %s=true", o.Namespace, APIAccessLabel, o.Namespace, APIAccessLabel)
	}
	return result(CheckAPIAccess, Pass, "", "namespace %s may reach ate-api-server", o.Namespace)
}
