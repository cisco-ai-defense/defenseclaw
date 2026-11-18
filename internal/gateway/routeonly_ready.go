// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Upstream credential of a route-only connector, as /health reports it.
const (
	routeCredentialAgent   = "agent"           // the agent credential is passed through
	routeCredentialHeld    = "gateway_held"    // a routing.models[].credential of the provider
	routeCredentialSigning = "gateway_signing" // the gateway signs Bedrock calls
	routeCredentialMissing = "missing"         // custody host without a gateway credential: every call is 503
)

// Closed causes of a route-only connector that is not ready, published next
// to the free-text problem (a code, never text from the config). doctor and
// the TUI read them from /health, and enterprise status and verify name them
// in the routing block (rel-1-0-10 GAP-1319), whose closed set they are.
const (
	routeCauseEpoch             = enterprisestatus.RoutingCauseRouteEpoch
	routeCauseAliasNoCredential = enterprisestatus.RoutingCauseAliasNoCredential
	routeCauseUpstreamNotSet    = enterprisestatus.RoutingCauseUpstreamNotSet
	routeCauseSigning           = enterprisestatus.RoutingCauseSigningNotReady
	routeCauseCredentialStored  = enterprisestatus.RoutingCauseCredentialNotStored
	routeCauseNoCredential      = enterprisestatus.RoutingCauseNoCredential
	routeCauseNoEnrolled        = enterprisestatus.RoutingCauseNoEnrolledAccount
)

// routeOnlyReadiness is the route-only state of one connector, published in
// /health routing.details.route_only so doctor, status and the TUI read it
// without a new endpoint.
type routeOnlyReadiness struct {
	Connector  string                     `json:"connector"`
	API        string                     `json:"api,omitempty"`
	Provider   string                     `json:"provider,omitempty"`
	Upstream   string                     `json:"upstream,omitempty"` // scheme://host only
	Custody    bool                       `json:"custody"`
	Credential string                     `json:"credential"`
	Signing    *routeOnlySigningReadiness `json:"signing,omitempty"`
	// EnrolledUsers counts the enrolled accounts of a managed host whose
	// route credential the gateway accepts (one per protected ledger row,
	// whether or not that account's route settings were written; verify
	// reports a missing render); nil off managed hosts.
	EnrolledUsers *int   `json:"enrolled_users,omitempty"`
	Ready         bool   `json:"ready"`
	Cause         string `json:"cause,omitempty"` // route* cause constants; "" for any other problem
	// Warning is a closed code for a state that leaves the connector ready
	// but refuses some callers (a scoped routing.admin rule).
	Warning string `json:"warning,omitempty"`
	// Detail names the rule and models behind Warning. Administrator only:
	// publicRouteOnly drops it (policy privacy, GAP-0666).
	Detail  string `json:"detail,omitempty"`
	Problem string `json:"problem,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// routeOnlySigningReadiness is the gateway Bedrock signing check.
type routeOnlySigningReadiness struct {
	Auth            string `json:"auth"`
	Profile         string `json:"profile,omitempty"`
	ProfileFound    *bool  `json:"profile_found,omitempty"`
	Region          string `json:"region,omitempty"`
	RegionOK        bool   `json:"region_ok"`
	RegionError     string `json:"region_error,omitempty"`
	Signer          bool   `json:"signer"`
	SignerError     string `json:"signer_error,omitempty"`
	Credential      bool   `json:"credential"`
	CredentialError string `json:"credential_error,omitempty"`
}

// awsRequestID matches the request id an AWS error carries; it changes on
// every call, so it is cut from readiness text (the periodic recheck would
// otherwise publish a new state, and wake every subscriber, each minute).
var awsRequestID = regexp.MustCompile(`(?i)(request ?id:? *)[0-9a-z-]{8,}`)

func readinessError(err error) string {
	return truncateUTF8(awsRequestID.ReplaceAllString(err.Error(), "${1}-"), 300)
}

// routeOnlyReadinessFor computes the readiness of every route-only connector
// of cfg (none when routing is off). Signing is checked with one bounded
// credential fetch through signers (the cache the listener signs with).
// It is published only while the route-only listener is mounted.
func routeOnlyReadinessFor(cfg *config.Config, goos string, signers *bedrockSigners, enrolled func(connector string) (int, bool)) []routeOnlyReadiness {
	names := routeOnlyConnectorsOf(cfg)
	if len(names) == 0 {
		return nil
	}
	managedHost := cfg.StandaloneEnterprise()
	custody := managedHost && routeOnlyCustodyOS(goos)
	out := make([]routeOnlyReadiness, 0, len(names))
	for _, name := range names {
		r := routeOnlyReadiness{Connector: name, Custody: custody}
		up, ok := cfg.Routing.RouteOnly.Upstreams[name]
		if !ok || strings.TrimSpace(up.BaseURL) == "" {
			r.Problem = "routing.route_only.upstreams." + name + " is not set"
			r.Cause = routeCauseUpstreamNotSet
			r.Fix = "set routing.route_only.upstreams." + name + " (base_url and api) in " + routeOnlyConfigSource(managedHost)
			out = append(out, r)
			continue
		}
		r.API, r.Provider, r.Upstream = up.API, config.RouteOnlyUpstreamProvider(up.API), originOf(up.BaseURL)
		switch {
		case bedrockGatewaySigning(up.Bedrock):
			r.Credential = routeCredentialSigning
			r.Signing = checkBedrockSigning(cfg, up.Bedrock, up.BaseURL, signers)
			r.Ready = r.Signing.RegionOK && r.Signing.Signer && r.Signing.Credential
			if !r.Ready {
				r.Cause = routeCauseSigning
				r.Problem = "gateway Bedrock signing is not ready"
				r.Fix = bedrockSigningFix(r.Signing, "routing.route_only.upstreams."+name+".bedrock", managedHost)
			}
		case custody:
			if routeOnlyHeldCredential(cfg, up.BaseURL, r.Provider) != "" {
				r.Credential, r.Ready = routeCredentialHeld, true
				break
			}
			r.Credential = routeCredentialMissing
			if named := routeOnlyCoveringCredentials(cfg, up.BaseURL, r.Provider); len(named) > 0 {
				// The bundle names the key, but this host does not store it.
				r.Cause = routeCauseCredentialStored
				r.Problem = "credential " + named[0] + " is named in the policy bundle but not stored on this host: every model call answers 503"
				r.Fix = "store it: defenseclaw-gateway enterprise secret set --name " + named[0] + " --from-stdin"
				break
			}
			r.Cause = routeCauseNoCredential
			r.Problem = "this managed host forwards no agent credential and no gateway credential covers " + r.Provider + " at " + r.Upstream + ": every model call answers 503"
			r.Fix = "set routing.models[].credential for " + r.Provider + " (base_url " + r.Upstream + ") in the policy bundle"
		default:
			r.Credential, r.Ready = routeCredentialAgent, true
		}
		if managedHost && r.Problem == "" {
			// An allowed alias without a gateway key refuses the calls of its
			// rule as "not allowed" (rel-1-0-10 GAP-0921). Only a rule for every
			// caller of the connector makes it not ready; a scoped rule is a
			// warning. The text names the rule and models; publicRouteOnly
			// removes it for an ordinary account (no credential on /health).
			blocking, scoped := routeOnlyAllowedWithoutKey(cfg, name, r.Provider)
			switch {
			case len(blocking) > 0:
				r.Ready, r.Cause = false, routeCauseAliasNoCredential
				r.Problem = "routing.admin rule " + blocking[0].ID + " applies to every " + name + " caller and allows only " + strings.Join(blocking[0].Aliases, ", ") + ", which has no gateway credential on this host: every call is refused"
				r.Fix = "name a protected credential in routing.models[].credential for " + strings.Join(blocking[0].Aliases, ", ") + " in the policy bundle and store its key: defenseclaw-gateway enterprise secret set --name <name> --from-stdin"
			case len(scoped) > 0:
				r.Warning = routeCauseAliasNoCredential
				r.Detail = "routing.admin rule " + scoped[0].ID + " (scoped to some callers) allows only " + strings.Join(scoped[0].Aliases, ", ") + ", which has no gateway credential on this host: those callers are refused"
			}
		}
		if managedHost && enrolled != nil {
			if n, ok := enrolled(name); ok {
				r.EnrolledUsers = &n
				if n == 0 && r.Problem == "" {
					// Nothing is routed until the guardian renders an
					// enrolled account (rel-1-0-10 GAP-0568: this was silent).
					r.Ready, r.Cause = false, routeCauseNoEnrolled
					r.Problem = "no enrolled account has " + name + " protected yet, so no " + name + " call is routed"
					r.Fix = "enroll users with " + name + " installed (enterprise.enrollment), wait for the hook guardian pass (about 2 minutes) and restart the agent; enterprise verify lists route_config_drift for an account whose route settings are missing"
				}
			}
		}
		out = append(out, r)
	}
	return out
}

func routeOnlyConfigSource(managedHost bool) string {
	if managedHost {
		return "the policy bundle"
	}
	return "config.yaml"
}

// bedrockSigningFix names the fix of the first failing signing check.
func bedrockSigningFix(s *routeOnlySigningReadiness, block string, managedHost bool) string {
	where := routeOnlyConfigSource(managedHost)
	switch {
	case !s.RegionOK:
		return "set " + block + ".region to the region of the upstream host in " + where
	case s.ProfileFound != nil && !*s.ProfileFound:
		return "create AWS profile " + s.Profile + " for the gateway account, or change " + block + ".profile in " + where
	case !s.Signer:
		return "fix " + block + " in " + where + ": the gateway could not build its Bedrock signer"
	default:
		return "refresh the AWS credentials of the gateway account (for SSO: aws sso login)"
	}
}

// checkBedrockSigning runs the doctor checks of gateway Bedrock signing:
// region consistent with the host, profile present, signer built, and one
// credential fetched within bedrockRenderCheckTimeout.
func checkBedrockSigning(cfg *config.Config, b *config.RoutingBedrockAuthConfig, baseURL string, signers *bedrockSigners) *routeOnlySigningReadiness {
	out := &routeOnlySigningReadiness{Auth: b.Auth}
	if b.Auth == config.RoutingBedrockAuthProfile {
		out.Profile = strings.TrimSpace(b.Profile)
		if out.Profile == "" {
			out.Profile = "default"
		}
	}
	region, err := bedrockSigningRegion(b, baseURL)
	if err != nil {
		out.RegionError = readinessError(err)
		return out
	}
	out.Region, out.RegionOK = region, true
	s, err := signers.get(cfg, b, baseURL)
	if err != nil {
		out.SignerError = readinessError(err)
		var missing awsconfig.SharedConfigProfileNotExistError
		if out.Profile != "" && errors.As(err, &missing) {
			out.ProfileFound = new(bool)
		}
		return out
	}
	out.Signer = true
	if out.Profile != "" {
		found := true
		out.ProfileFound = &found
	}
	ctx, cancel := context.WithTimeout(context.Background(), bedrockRenderCheckTimeout)
	defer cancel()
	if _, err := s.creds.Retrieve(ctx); err != nil {
		out.CredentialError = readinessError(err)
		return out
	}
	out.Credential = true
	return out
}

// Route-only readiness is recomputed on a config change and at least this
// often (the credential fetch is cached by the SDK between refreshes).
var (
	routeOnlyReadinessPoll  = 2 * time.Second
	routeOnlyReadinessEvery = time.Minute
)

// runRouteOnlyReadiness keeps /health routing.details.route_only current.
func (s *Sidecar) runRouteOnlyReadiness(ctx context.Context, ro *routeOnlyServer) {
	if s == nil || s.health == nil || ro == nil {
		return
	}
	var last *config.Config
	var lastAt time.Time
	tick := time.NewTicker(routeOnlyReadinessPoll)
	defer tick.Stop()
	for {
		if cfg := s.currentConfig(); cfg != last || time.Since(lastAt) >= routeOnlyReadinessEvery {
			s.health.SetRouteOnlyReadiness(withRouteEpochReadiness(routeOnlyReadinessFor(cfg, ro.goos, &ro.signers, ro.enrolledRouteUsers), ro.routeEpochUnpublished()))
			last, lastAt = cfg, time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// withRouteEpochReadiness marks every route-only connector not ready while
// the managed Windows route epoch is not published: the guardian derives
// each account's route credential from it, so nothing can be rendered
// (rel-1-0-10:GAP-0800). problem "" changes nothing.
func withRouteEpochReadiness(out []routeOnlyReadiness, problem string) []routeOnlyReadiness {
	if problem == "" {
		return out
	}
	for i := range out {
		if out[i].Problem == "" {
			out[i].Cause = routeCauseEpoch
			out[i].Problem = problem + ", so the hook guardian cannot render route-only for any account"
			out[i].Fix = "check gateway.log for 'route epoch not published' (the machine data dir hooks folder must be writable by the gateway service), then restart DefenseClawGateway"
		}
		out[i].Ready = false
	}
	return out
}

// publicRouteOnlyProblems is what an ordinary account reads for each closed
// cause. It names no credential, model, alias, rule, group, path or user.
var publicRouteOnlyProblems = map[string]string{
	routeCauseEpoch:             "the gateway route epoch is not ready, so no account can be rendered",
	routeCauseAliasNoCredential: "a routing.admin rule that applies to every caller allows only models with no gateway credential on this host: every call is refused",
	routeCauseUpstreamNotSet:    "the route-only upstream is not set",
	routeCauseSigning:           "gateway Bedrock signing is not ready",
	routeCauseCredentialStored:  "a gateway credential the policy names is not stored on this host: every model call is refused",
	routeCauseNoCredential:      "no gateway credential covers the route-only upstream: every model call is refused",
	routeCauseNoEnrolled:        "no enrolled account has the connector protected yet",
}

// publicRouteOnlyFix is the next step an ordinary account of a managed host
// reads. doctor is refused on a managed Windows host, so there it names the
// administrator status command, which prints the cause (rel-1-0-10 GAP-1319).
func publicRouteOnlyFix(goos string) string {
	if goos == "windows" {
		return "an administrator reads the cause in an elevated PowerShell prompt with " +
			managed.WindowsGatewayCommand("enterprise", "windows", "status") + " (verify names it too)"
	}
	return "run defenseclaw doctor as an administrator for the cause and the fix"
}

// publicRouteOnly is a route-only readiness row as an ordinary account may
// read it on a standalone host: the closed cause and warning codes and
// generic text, never a credential, model, rule or path name, a signing
// profile or an upstream (policy privacy, rel-1-0-10 GAP-0666, GAP-1268).
func publicRouteOnly(in routeOnlyReadiness) routeOnlyReadiness {
	out := routeOnlyReadiness{
		Connector: in.Connector, API: in.API, Provider: in.Provider, Custody: in.Custody, Credential: in.Credential,
		EnrolledUsers: in.EnrolledUsers, Ready: in.Ready, Cause: in.Cause, Warning: in.Warning,
	}
	if !in.Ready {
		out.Problem = publicRouteOnlyProblems[in.Cause]
		if out.Problem == "" {
			out.Problem = "route-only is not ready"
		}
		out.Fix = publicRouteOnlyFix(runtime.GOOS)
	}
	return out
}

// healthRoutingForOrdinaryAccount replaces the route-only rows of the
// routing subsystem with their public form (a copy; the stored details are
// never written).
func healthRoutingForOrdinaryAccount(routing SubsystemHealth) SubsystemHealth {
	if routing.LastError != "" {
		// The start error can quote a path, a credential or a model of the
		// policy; an ordinary account reads a closed text, like config. The text
		// points to status, not doctor: doctor reads this very row.
		routing.LastError = "routing did not start; an administrator can read the cause in defenseclaw status"
	}
	rows, ok := routing.Details["route_only"].([]routeOnlyReadiness)
	if !ok {
		return routing
	}
	public := make([]routeOnlyReadiness, len(rows))
	for i, row := range rows {
		public[i] = publicRouteOnly(row)
	}
	details := make(map[string]interface{}, len(routing.Details))
	for k, v := range routing.Details {
		details[k] = v
	}
	details["route_only"] = public
	routing.Details = details
	return routing
}
