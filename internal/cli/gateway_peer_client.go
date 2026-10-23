// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var perUserGatewayClientFactory = hookexec.NewPerUserGatewayHTTPClient

// gatewayPeerClient is the transport for Go CLI requests to a per-user
// gateway. The socket owner is checked after Dial, before net/http can send
// a token, scan target, or telemetry fact. Managed gateways use their
// service-specific identity checks instead of a same-account requirement.
func gatewayPeerClient(c *config.Config, host string, port int, timeout time.Duration) (*http.Client, error) {
	if c != nil && c.SecureClientIntegration() && secureClientHost() {
		return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: refuseGatewayPeerRedirect}, nil
	}
	if _, present := managedHostWindowsStandalone(); present &&
		(c == nil || c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode)) {
		return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: refuseGatewayPeerRedirect}, nil
	}
	if c != nil && (c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode)) {
		return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: refuseGatewayPeerRedirect}, nil
	}
	return perUserGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)))
}

func gatewayPeerClientForURL(c *config.Config, rawURL string, timeout time.Duration) (*http.Client, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Hostname() == "" {
		return nil, fmt.Errorf("gateway target is not a local HTTP endpoint")
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("gateway target port is invalid")
	}
	return gatewayPeerClient(c, target.Hostname(), port, timeout)
}

func refuseGatewayPeerRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
