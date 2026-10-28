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

// managedGatewayClientFactory waits out a managed gateway that runs but is
// not listening yet: a scan right after secret set restarted the gateway
// failed at once with "running service has no listener yet" (GAP-2442).
var managedGatewayClientFactory = func(timeout time.Duration, apiAddr, serviceName string) (*http.Client, error) {
	return hookexec.NewManagedEnterpriseGatewayHTTPClientAwaitingStart(timeout, apiAddr, serviceName, managedGatewayStartBudget)
}

// managedGatewayStartBudget bounds how long a CLI command waits for a
// starting managed gateway to listen.
const managedGatewayStartBudget = 30 * time.Second

// gatewayPeerClient is the transport for Go CLI requests to a per-user
// gateway. The socket owner is checked after Dial, before net/http can send
// a token, scan target, or telemetry fact. Managed gateways use their
// service-specific identity checks instead of a same-account requirement.
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
