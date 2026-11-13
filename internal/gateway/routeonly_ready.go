// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
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
	Mounted    bool                       `json:"mounted"`
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

func readinessError(err error) string { return truncateUTF8(err.Error(), 300) }

// routeOnlyReadinessFor computes the readiness of every route-only connector
// of cfg (none when routing is off). Signing is checked with one bounded
// credential fetch through signers (the cache the listener signs with).
func routeOnlyReadinessFor(cfg *config.Config, goos string, signers *bedrockSigners, mounted bool) []routeOnlyReadiness {
	names := routeOnlyConnectorsOf(cfg)
	if len(names) == 0 {
		return nil
	}
	managedHost := cfg.StandaloneEnterprise()
	custody := managedHost && routeOnlyCustodyOS(goos)
	out := make([]routeOnlyReadiness, 0, len(names))
	for _, name := range names {
		r := routeOnlyReadiness{Connector: name, Mounted: mounted, Custody: custody}
		up, ok := cfg.Routing.RouteOnly.Upstreams[name]
		if !ok || strings.TrimSpace(up.BaseURL) == "" {
			r.Problem = "routing.route_only.upstreams." + name + " is not set"
			r.Fix = "run defenseclaw routing enable --connector " + name
			if managedHost {
				r.Fix = "set routing.route_only.upstreams." + name + " in the policy bundle"
			}
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
				r.Fix = "check routing.route_only.upstreams." + name + ".bedrock (run defenseclaw doctor for the failing check)"
			}
		case custody:
			if routeOnlyHeldCredential(cfg, up.BaseURL, r.Provider) != "" {
				r.Credential, r.Ready = routeCredentialHeld, true
				break
			}
			r.Credential = routeCredentialMissing
			r.Problem = "this managed host forwards no agent credential and no gateway credential covers " + r.Provider + " at " + r.Upstream + ": every model call answers 503"
			r.Fix = "set routing.models[].credential for " + r.Provider + " (base_url " + r.Upstream + ") in the policy bundle"
		default:
			r.Credential, r.Ready = routeCredentialAgent, true
		}
		if r.Ready && !mounted {
			r.Ready, r.Problem = false, "the route-only listener is not mounted on the gateway API"
			r.Fix = "restart the gateway"
		}
		out = append(out, r)
	}
	return out
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
			s.health.SetRouteOnlyReadiness(routeOnlyReadinessFor(cfg, ro.goos, &ro.signers, true))
			last, lastAt = cfg, time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
