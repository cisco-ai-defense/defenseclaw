// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// enterpriseEgress is the standalone gateway's enterprise.network proxy.
// SetEnterpriseEgress installs it once when the gateway process starts,
// before any outbound client exists; edits to the enterprise block require a
// restart, so it does not change while the gateway runs. The outbound
// clients read it when they connect (the passthrough client is a
// package-level value built before startup).
var enterpriseEgress atomic.Pointer[netguard.EgressRoute]

// SetEnterpriseEgress sends the gateway's own outbound clients through the
// administrator's enterprise.network proxy in the standalone profile: LLM
// calls made through Bifrost (the judge and the guardrail proxy), the LLM
// passthrough, webhooks, the remote model router and every telemetry
// exporter (OTLP over HTTP and gRPC, Splunk HEC, HTTP JSONL). Each client
// keeps its own destination check; the route only changes how a checked
// destination is reached. The AI Defense client takes the same proxy from
// its own transport, and clients on Go's default transport take it from the
// process environment. Outside the standalone profile, or without a proxy,
// the route is cleared and every client connects as before.
func SetEnterpriseEgress(cfg *config.Config) error {
	var route *netguard.EgressRoute
	if cfg != nil && cfg.StandaloneEnterprise() {
		compiled, err := cfg.Enterprise.EgressProxy().Route()
		if err != nil {
			return fmt.Errorf("enterprise.network: %w", err)
		}
		route = compiled
	}
	enterpriseEgress.Store(route)
	return nil
}

func currentEnterpriseEgress() *netguard.EgressRoute {
	return enterpriseEgress.Load()
}

// enterpriseEgressDialer connects through the current enterprise route over
// direct. It is the dialer below the telemetry exporters' destination check,
// and the whole connection layer of clients that have no check of their own.
type enterpriseEgressDialer struct {
	direct netguard.V8Dialer
}

func (d enterpriseEgressDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return currentEnterpriseEgress().Dial(ctx, d.direct, network, address)
}

// bifrostEgressProxy is the Bifrost proxy setting for an LLM provider
// endpoint under route. Bifrost's provider clients do not read the process
// environment, so the route is applied explicitly: nil without a route or
// when no_proxy (or loopback) excludes the endpoint, otherwise the proxy. An
// empty endpoint is the provider's public default and goes through the
// proxy. Bifrost opens only plain-HTTP connections to a proxy, so an
// https:// proxy is refused here instead of letting the provider connect
// directly.
func bifrostEgressProxy(route *netguard.EgressRoute, endpoint string) (*schemas.ProxyConfig, error) {
	if route == nil {
		return nil, nil
	}
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		if !strings.Contains(endpoint, "://") {
			endpoint = "https://" + endpoint
		}
		target, err := url.Parse(endpoint)
		if err != nil || target.Host == "" {
			return nil, fmt.Errorf("enterprise.network: LLM endpoint %q is not a URL", endpoint)
		}
		proxied, err := route.Proxies(target)
		if err != nil {
			return nil, fmt.Errorf("enterprise.network: %w", err)
		}
		if !proxied {
			return nil, nil
		}
	}
	proxyURL := route.URL()
	if proxyURL.Scheme != "http" {
		return nil, fmt.Errorf("enterprise.network.https_proxy %s: LLM provider connections need an http:// proxy URL (the provider client cannot open TLS to the proxy)", proxyURL.Redacted())
	}
	return &schemas.ProxyConfig{Type: schemas.HTTPProxy, URL: &schemas.SecretVar{Val: proxyURL.String()}}, nil
}
