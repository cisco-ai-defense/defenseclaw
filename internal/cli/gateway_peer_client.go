// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var perUserGatewayClientFactory = hookexec.NewPerUserGatewayHTTPClient
var managedGatewayClientFactory = hookexec.NewManagedEnterpriseGatewayHTTPClient

// gatewayPeerClient is the transport for Go CLI requests to the local
// gateway. The owner of the connected socket is checked after Dial, before
// net/http can send a token, scan target, or telemetry fact: this account
// for a per-user gateway, the gateway service for a managed one. While a
// gateway restarts another account can bind its port; it receives nothing.
func gatewayPeerClient(c *config.Config, host string, port int, timeout time.Duration) (*http.Client, error) {
	if c != nil && c.SecureClientIntegration() && secureClientHost() {
		return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), managedServiceName(true))
	}
	if _, present := managedHostWindowsStandalone(); present &&
		(c == nil || c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode)) {
		return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), managed.StandaloneWindowsGatewaySvc)
	}
	if c != nil && (c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode)) {
		return managedGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)), managedServiceName(false))
	}
	return perUserGatewayClientFactory(timeout, net.JoinHostPort(host, strconv.Itoa(port)))
}

func managedServiceName(secureClient bool) string {
	if runtime.GOOS == "linux" {
		return "defenseclaw-gateway.service"
	}
	if runtime.GOOS == "darwin" {
		if secureClient {
			return "com.cisco.secureclient.defenseclaw"
		}
		return "com.cisco.defenseclaw.gateway"
	}
	return managed.StandaloneWindowsGatewaySvc
}

func gatewayPeerClientForURL(c *config.Config, rawURL string, timeout time.Duration) (*http.Client, error) {
	host, port, err := localGatewayURLEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	return gatewayPeerClient(c, host, port, timeout)
}

func localGatewayURLEndpoint(rawURL string) (string, int, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "http" || target.User != nil || target.Hostname() == "" {
		return "", 0, fmt.Errorf("gateway target is not a local HTTP endpoint")
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("gateway target port is invalid")
	}
	return target.Hostname(), port, nil
}
