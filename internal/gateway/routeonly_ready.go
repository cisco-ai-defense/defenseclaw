// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Upstream credential of a route-only connector, as /health reports it.
const (
	routeCredentialAgent   = "agent"           // the agent credential is passed through
	routeCredentialHeld    = "gateway_held"    // a routing.models[].credential of the provider
	routeCredentialSigning = "gateway_signing" // the gateway signs Bedrock calls
	routeCredentialMissing = "missing"         // custody host without a gateway credential: every call is 503
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
	Ready      bool                       `json:"ready"`
	Problem    string                     `json:"problem,omitempty"`
	Fix        string                     `json:"fix,omitempty"`
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
func routeOnlyReadinessFor(cfg *config.Config, goos string, signers *bedrockSigners) []routeOnlyReadiness {
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
				r.Problem = "credential " + named[0] + " is named in the policy bundle but not stored on this host: every model call answers 503"
				r.Fix = "store it: defenseclaw-gateway enterprise secret set --name " + named[0] + " --from-stdin"
				break
			}
			r.Problem = "this managed host forwards no agent credential and no gateway credential covers " + r.Provider + " at " + r.Upstream + ": every model call answers 503"
			r.Fix = "set routing.models[].credential for " + r.Provider + " (base_url " + r.Upstream + ") in the policy bundle"
		default:
			r.Credential, r.Ready = routeCredentialAgent, true
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
			s.health.SetRouteOnlyReadiness(routeOnlyReadinessFor(cfg, ro.goos, &ro.signers))
			last, lastAt = cfg, time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
